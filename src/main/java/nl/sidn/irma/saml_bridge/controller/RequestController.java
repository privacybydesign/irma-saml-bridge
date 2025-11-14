package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.model.IrmaPath;
import nl.sidn.irma.saml_bridge.model.RequestError;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.IrmaService;
import nl.sidn.irma.saml_bridge.service.OpenSamlService;
import nl.sidn.irma.saml_bridge.service.SignatureValidationService;
import nl.sidn.irma.saml_bridge.util.HTTPRedirectDeflateDecoder;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.impl.XSStringImpl;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

@Slf4j
@Controller
@RequestMapping("/request")
public class RequestController {

    private final ObjectMapper objectMapper;
    private final SignatureValidationService signatureValidationService;
    private final ConfigurationService configurationService;
    private final OpenSamlService openSamlService;
    private final JwtUtil jwtUtil;
    private final IrmaService irmaService;
    private final HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder;

    public RequestController(final ObjectMapper objectMapper, final SignatureValidationService signatureValidationService, final ConfigurationService configurationService, final OpenSamlService openSamlService, final JwtUtil jwtUtil, final IrmaService irmaService, final HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder) {
        this.objectMapper = objectMapper;
        this.signatureValidationService = signatureValidationService;
        this.configurationService = configurationService;
        this.openSamlService = openSamlService;
        this.jwtUtil = jwtUtil;
        this.irmaService = irmaService;
        this.httpRedirectDeflateDecoder = httpRedirectDeflateDecoder;
    }

    /**
     * Internal exception used to short-circuit the flow and map directly to a RequestError.
     */
    @Getter
    private static class RequestProcessingException extends RuntimeException {
        private final RequestError requestError;

        private RequestProcessingException(final RequestError requestError) {
            this.requestError = requestError;
        }

    }

    private record IrmaRouting(String host, String postfix, String irmaServiceBaseUrl) {
    }

    /**
     * Prepare the response to show an error message instead of the default interaction.
     */
    private String showError(final RequestError requestError, final HttpServletRequest request, final HttpServletResponse response, final Model model) throws JsonProcessingException {
        final AssertParameters assertParameters = AssertParameters.builder().requestError(requestError).build();

        response.setStatus(requestError.getStatusCode());
        response.setContentType("text/html");
        request.setAttribute("error", requestError.getMessage());
        request.setAttribute("assert_parameters", jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));

        model.addAttribute("request", request);
        // Show same page as always, let React render error
        return "irma-request";
    }

    @GetMapping
    public String request(final HttpServletRequest request, final HttpServletResponse response, final Model model) throws IOException, ServletException {

        final Configuration config = configurationService.getConfiguration();
        final String ourPostfix = config.getPostfix();

        setErrorUrls(request, ourPostfix);

        try {
            initializeDecoder(request);
            final MessageContext messageContext = decodeSamlRequest();
            final AuthnRequest authnRequest = extractAuthnRequest(messageContext);
            final EntityDescriptor entityDescriptor = verifySignature(request, messageContext);
            validateIssueInstant(authnRequest, config);

            final String[][][] condiscon = resolveCondiscon(authnRequest, config);
            final String returnUrl = resolveReturnUrl(authnRequest, entityDescriptor);
            final String spName = resolveSpName(authnRequest);
            final IrmaRouting routing = resolveIrmaRouting(config, spName);

            final String token = buildIrmaJwtToken(condiscon, routing.host());
            final String irmaSessionData = startIrmaSession(token, routing.irmaServiceBaseUrl(), routing.postfix());

            // Use a URL with the external host to prevent CORS issues.
            final String externalIrmaServiceBaseUrl = config.getProtocol() + routing.host();

            prepareIrmaRequestAttributes(request, response, ourPostfix, externalIrmaServiceBaseUrl, routing.postfix(), irmaSessionData);

            final String repackedCondiscon = objectMapper.writeValueAsString(condiscon);

            // Create the JWT parameters used by this daemon to formulate a SAML Assertion.
            final AssertParameters assertParameters = buildAssertParameters(authnRequest, spName, returnUrl, repackedCondiscon, request);

            setAssertionJwtOnRequest(request, assertParameters);

            response.setContentType("text/html");
            model.addAttribute("request", request);
            return "irma-request";

        } catch (final RequestProcessingException requestError) {
            try {
                return showError(requestError.getRequestError(), request, response, model);
            } catch (final JsonProcessingException ex) {
                // Fallback: if showError fails JSON-wise, still log and send generic 500.
                log.error("action=\"request-flow\", error=\"Failed to render error response\"", ex);
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                return "irma-request";
            }
        }
    }

    // ------------------- private helper methods -------------------

    private void setErrorUrls(final HttpServletRequest request, final String ourPostfix) {
        request.setAttribute("error_assert_url", ourPostfix + "/errorassert");
        request.setAttribute("error_url", ourPostfix + "/report");
    }

    private void initializeDecoder(final HttpServletRequest request) {
        httpRedirectDeflateDecoder.setHttpServletRequest(request);
        try {
            httpRedirectDeflateDecoder.initialize();
        } catch (final ComponentInitializationException e) {
            log.error("action=\"request-flow\", error=\"Failed to initialize OpenSAML decoder\"", e);
            throw error(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to initialize OpenSAML decoder");
        }
    }

    private MessageContext decodeSamlRequest() {
        try {
            httpRedirectDeflateDecoder.decode();
        } catch (final MessageDecodingException e) {
            log.warn("action=\"request-flow\", warning=\"Failed to decode SAML request\"", e);
            throw error(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to decode SAML request");
        }
        return httpRedirectDeflateDecoder.getMessageContext();
    }

    private AuthnRequest extractAuthnRequest(final MessageContext messageContext) {
        final AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
        if (authnRequest == null) {
            log.warn("action=\"request-flow\", warning=\"SAML request is not an Authnrequest\"");
            throw error(HttpStatus.BAD_REQUEST, "SAML request is not an Authnrequest");
        }
        return authnRequest;
    }

    private EntityDescriptor verifySignature(final HttpServletRequest request, final MessageContext messageContext) {
        try {
            return signatureValidationService.verifySignature(request, messageContext);
        } catch (final MessageHandlerException | ComponentInitializationException | ResolverException e) {
            log.warn("action=\"request-flow\", warning=\"SAML request signature malformed\"", e);
            throw error(HttpStatus.UNAUTHORIZED, "SAML request signature malformed");
        }
    }

    private void validateIssueInstant(final AuthnRequest authnRequest, final Configuration config) {
        if (authnRequest.getIssueInstant().isBefore(Instant.now().minusSeconds(config.getRequestTtlInSec()))) {
            log.warn("action=\"request-flow\", warning=\"SAML request is too old, session timeout\"");
            throw error(HttpStatus.BAD_REQUEST, "SAML request is too old, session timeout");
        }
    }

    private String[][][] resolveCondiscon(final AuthnRequest authnRequest, final Configuration config) {
        final Extensions extensions = authnRequest.getExtensions();

        String packedCondiscon = null;
        final Map<String, Set<String>> simpleAttributes = new TreeMap<>();

        if (extensions != null) {
            final List<Attribute> xmlAttributes = collectXmlAttributes(extensions);
            for (final Attribute xmlAttribute : xmlAttributes) {
                final String attributeName = xmlAttribute.getName();

                if (attributeName.split("\\.").length == 4) {
                    handleSimpleAttribute(xmlAttribute, attributeName, simpleAttributes);
                } else if (attributeName.contains("condiscon")) {
                    packedCondiscon = handlePackedCondiscon(xmlAttribute, packedCondiscon);
                } else {
                    log.warn("action=\"request-flow\", warning=\"Requested XML attribute name is invalid\"");
                    throw error(HttpStatus.BAD_REQUEST, "Requested XML attribute name is invalid");
                }
            }
        }

        return buildCondisconFromInputs(authnRequest, config, packedCondiscon, simpleAttributes);
    }

    private List<Attribute> collectXmlAttributes(final Extensions extensions) {
        final List<Attribute> xmlAttributes = new ArrayList<>();
        final List<XMLObject> extensionsList = extensions.getOrderedChildren();
        if (extensionsList != null) {
            for (final XMLObject extension : extensionsList) {
                if (extension instanceof final RequestedAttributes requestedAttributes) {
                    xmlAttributes.addAll(requestedAttributes.getRequestedAttributes());
                } else if (extension instanceof final Attribute attribute) {
                    xmlAttributes.add(attribute);
                }
            }
        }
        return xmlAttributes;
    }

    private void handleSimpleAttribute(final Attribute xmlAttribute, final String attributeName, final Map<String, Set<String>> simpleAttributes) {
        if (xmlAttribute instanceof RequestedAttribute) {
            final String credentialName = attributeName.substring(0, attributeName.lastIndexOf("."));
            final Set<String> list = simpleAttributes.computeIfAbsent(credentialName, k -> new TreeSet<>());
            if (list.contains(attributeName)) {
                log.warn("action=\"request-flow\", warning=\"Cannot request the same irma attribute identifier multiple times\"");
                throw error(HttpStatus.BAD_REQUEST, "Cannot request the same irma attribute identifier multiple times");
            }
            list.add(attributeName);
        } else {
            log.warn("action=\"request-flow\", warning=\"Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension\"");
            throw error(HttpStatus.BAD_REQUEST, "Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension");
        }
    }

    private String handlePackedCondiscon(final Attribute xmlAttribute, String packedCondiscon) {
        for (final XMLObject attributeValue : xmlAttribute.getAttributeValues()) {
            if (packedCondiscon != null) {
                log.warn("action=\"request-flow\", warning=\"Cannot request for multiple condiscons\"");
                throw error(HttpStatus.BAD_REQUEST, "Cannot request for multiple condiscons");
            }
            try {
                final XSStringImpl attributeValueAny = (XSStringImpl) attributeValue;
                packedCondiscon = attributeValueAny.getValue();
            } catch (final ClassCastException ignored) {
                // No-op, ignore
            }
        }
        return packedCondiscon;
    }

    private String[][][] buildCondisconFromInputs(final AuthnRequest authnRequest, final Configuration config, final String packedCondiscon, final Map<String, Set<String>> simpleAttributes) {
        final String[][][] condiscon;

        if (!simpleAttributes.isEmpty()) {
            if (packedCondiscon != null) {
                log.warn("action=\"request-flow\", warning=\"Cannot mix the condiscon and the requested attributes extension\"");
                throw error(HttpStatus.BAD_REQUEST, "Cannot mix the condiscon and the requested attributes extension");
            }
            condiscon = new String[simpleAttributes.size()][][];
            int i = 0;
            for (final Set<String> attributes : simpleAttributes.values()) {
                condiscon[i++] = new String[][]{attributes.toArray(new String[0])};
            }
        } else if (StringUtils.isNotEmpty(packedCondiscon)) {
            try {
                condiscon = objectMapper.readValue(packedCondiscon, String[][][].class);
            } catch (final JsonProcessingException e) {
                log.warn("action=\"request-flow\", warning=\"Requested condiscon could not be parsed\"", e);
                throw error(HttpStatus.BAD_REQUEST, "Requested condiscon could not be parsed");
            }
        } else {
            condiscon = resolveCondisconFromNameIdPolicyOrDefault(authnRequest, config);
        }

        return condiscon;
    }

    private String[][][] resolveCondisconFromNameIdPolicyOrDefault(final AuthnRequest authnRequest, final Configuration config) {
        String[][][] condiscon = null;
        final NameIDPolicy nameIdPolicy = authnRequest.getNameIDPolicy();

        if (nameIdPolicy != null) {
            final String nameIdPolicyFormat = nameIdPolicy.getFormat();
            if (nameIdPolicyFormat != null) {
                try {
                    condiscon = objectMapper.readValue(nameIdPolicyFormat, String[][][].class);
                } catch (final Exception e) {
                    log.warn("Could not convert nameIdPolicy format to a condiscons array with error: {}", e.getMessage());
                }
            }
        }

        if (condiscon == null) {
            log.warn("action=\"request-flow\", warning=\"Requested attributeType is empty\"");
            condiscon = config.getDefaultCondiscon();
        }

        return condiscon;
    }

    private String resolveReturnUrl(final AuthnRequest authnRequest, final EntityDescriptor entityDescriptor) {
        String returnUrl = authnRequest.getAssertionConsumerServiceURL();
        if (StringUtils.isEmpty(returnUrl)) {
            log.debug("action=\"request-flow\", debug=\"Using default AssertionConsumerServiceURL from metadata\"");
            returnUrl = openSamlService.findRedirectAssertionConsumerService(entityDescriptor);
        }

        if (StringUtils.isEmpty(returnUrl)) {
            log.warn("action=\"request-flow\", warning=\"Return URL is empty (AssertionConsumerServiceURL in SAML)\"");
            throw error(HttpStatus.BAD_REQUEST, "Return URL is empty (AssertionConsumerServiceURL in SAML)");
        }

        return returnUrl;
    }

    private String resolveSpName(final AuthnRequest authnRequest) {
        String spName = authnRequest.getProviderName();
        if (spName == null) {
            spName = "test";
        } else {
            spName = spName.toLowerCase();
        }
        return spName;
    }

    private IrmaRouting resolveIrmaRouting(final Configuration config, final String spName) {
        final Map<String, IrmaPath> mapping = config.getIrmaMapping();
        final IrmaPath path = mapping.get(spName);

        final String protocol = config.getProtocol();
        String host;
        String postfix;
        final String irmaServiceBaseUrl;

        if (path == null) {
            // No specific mapping found, use generic mapping.
            host = config.getDefaultMap().getHost();
            irmaServiceBaseUrl = protocol + config.getDefaultMap().getIrmaServiceHost();
            postfix = config.getDefaultMap().getPostfix();
        } else {
            // Use specific mapping.
            host = path.getHost();
            irmaServiceBaseUrl = protocol + path.getIrmaServiceHost();
            postfix = path.getPostfix();
        }

        host = host.replace("{spName}", spName);
        postfix = postfix.replace("{spName}", spName);
        return new IrmaRouting(host, postfix, irmaServiceBaseUrl);
    }

    private String buildIrmaJwtToken(final String[][][] condiscon, final String host) {
        final TreeMap<String, Object> content = new TreeMap<>();
        content.put("@context", "https://irma.app/ld/request/disclosure/v2");
        content.put("disclose", condiscon);
        content.put("host", host);

        final TreeMap<String, Object> sprequest = new TreeMap<>();
        sprequest.put("request", content);
        sprequest.put("validity", 30); // Seconds that JWT session result is valid
        // sprequest.put("timeout", 240);

        return jwtUtil.createJwtToken("verification_request", "sprequest", sprequest);
    }

    private String startIrmaSession(final String token, final String irmaServiceBaseUrl, final String postfix) {
        try {
            return irmaService.startSession(token, irmaServiceBaseUrl + postfix);
        } catch (final BridgeException e) {
            // logging already done in irmaService
            throw new RequestProcessingException(RequestError.builder().statusCode(e.getHttpStatusCode()).message(e.getMessage()).build());
        }
    }

    private void prepareIrmaRequestAttributes(final HttpServletRequest request, final HttpServletResponse response, final String ourPostfix, final String externalIrmaServiceBaseUrl, final String postfix, final String irmaSessionData) {
        request.setAttribute("irma_server", externalIrmaServiceBaseUrl + postfix);

        // The frontend has no support for switching languages in the middle of a
        // session. Therefore, we hardcode the language for now.
        // TODO: Check whether Signicat gives us a language to use. Otherwise, add
        // support in irma-web to switch language manually.
        request.setAttribute("language", "nl");
        request.setAttribute("session_data", irmaSessionData);
        request.setAttribute("assert_url", ourPostfix + "/assert");

        // The user browser is going to communicate with our IRMA server,
        // which is under the guise of a client hostname.
        // As such we need to give permission to perform an AJAX request to that
        // hostname.
        response.setHeader("Access-Control-Allow-Origin", externalIrmaServiceBaseUrl);
    }

    private AssertParameters buildAssertParameters(final AuthnRequest authnRequest, final String spName, final String returnUrl, final String repackedCondiscon, final HttpServletRequest request) {
        final String issuer = authnRequest.getIssuer().getValue();

        return AssertParameters.builder().spName(spName).requestId(authnRequest.getID()).serviceUrl(returnUrl).issuer(issuer).condiscon(repackedCondiscon).relayState(request.getParameter("RelayState")).build();
    }

    private void setAssertionJwtOnRequest(final HttpServletRequest request, final AssertParameters assertParameters) throws JsonProcessingException {
        request.setAttribute("assert_parameters", jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));
    }

    private RequestProcessingException error(final HttpStatus status, final String message) {
        return new RequestProcessingException(RequestError.builder().statusCode(status.value()).message(message).build());
    }
}
