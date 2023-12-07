package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    public RequestController(
            ObjectMapper objectMapper,
            SignatureValidationService signatureValidationService,
            ConfigurationService configurationService,
            OpenSamlService openSamlService,
            JwtUtil jwtUtil,
            IrmaService irmaService) {
        this.objectMapper = objectMapper;
        this.signatureValidationService = signatureValidationService;
        this.configurationService = configurationService;
        this.openSamlService = openSamlService;
        this.jwtUtil = jwtUtil;
        this.irmaService = irmaService;
    }

    /**
     * Prepare the response to show an error message instead of the default
     * interaction.
     * The error message gets rendered by React. We only provide which error should
     * be
     * shown, and leave all template parameters empty.
     *
     * @param requestError The request error.
     * @param response     The servlet response.
     * @param model        The servlet response.
     */
    private String showError(
            RequestError requestError,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) throws JsonProcessingException {
        AssertParameters assertParameters = AssertParameters.builder()
                .requestError(requestError)
                .build();

        response.setStatus(requestError.getStatusCode());
        response.setContentType("text/html");
        request.setAttribute("error", requestError.getMessage());
        request.setAttribute("assert_parameters",
                jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));

        model.addAttribute("request", request);
        // Show same page as always, let React render error
        return "irma-request";
    }

    @GetMapping
    public String request(
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) throws IOException, ServletException {

        Configuration config = this.configurationService.getConfiguration();
        String ourPostfix = config.getPostfix();

        // first set the error url's on the request as parameter, so the error can be
        // used in the SAML response
        request.setAttribute("error_assert_url", ourPostfix + "/errorassert");
        request.setAttribute("error_url", ourPostfix + "/report");

        HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder();
        httpRedirectDeflateDecoder.setHttpServletRequest(request);
        try {
            httpRedirectDeflateDecoder.initialize();
        } catch (ComponentInitializationException e) {
            // It is unclear when this will happen, and should basically never happen.
            log.error("action=\"request-flow\", error=\"Failed to initialize OpenSAML decoder\"", e);
            return showError(
                    RequestError.builder()
                            .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                            .message("Failed to initialize OpenSAML decoder")
                            .build(),
                    request,
                    response,
                    model);
        }

        // Actually decode the SAML request.
        try {
            httpRedirectDeflateDecoder.decode();
        } catch (MessageDecodingException e) {
            log.warn("action=\"request-flow\", warning=\"Failed to decode SAML request\"", e);
            return showError(RequestError.builder()
                    .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .message("Failed to decode SAML request")
                    .build(),
                    request,
                    response,
                    model);
        }

        MessageContext messageContext = httpRedirectDeflateDecoder.getMessageContext();

        // Extract what kind of attributes we want to request using IRMA
        // from the 'NameIDPolicy' field of the SAML request.
        AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
        if (authnRequest == null) {
            log.warn("action=\"request-flow\", warning=\"SAML request is not an Authnrequest\"");
            return showError(RequestError.builder()
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .message("SAML request is not an Authnrequest")
                    .build(),
                    request,
                    response,
                    model);
        }

        // Check the signature and find out from which entity this message originated.
        EntityDescriptor entityDescriptor;
        try {
            entityDescriptor = signatureValidationService.verifySignature(request, messageContext);
        } catch (MessageHandlerException | ComponentInitializationException | ResolverException e) {
            log.warn("action=\"request-flow\", warning=\"SAML request signature malformed\"", e);
            return showError(RequestError.builder()
                    .statusCode(HttpStatus.UNAUTHORIZED.value())
                    .message("SAML request signature malformed")
                    .build(),
                    request,
                    response,
                    model);
        }

        if (authnRequest.getIssueInstant().isBefore(Instant.now().minusSeconds(config.getRequestTtlInSec()))) {
            log.warn("action=\"request-flow\", warning=\"SAML request is too old, session timeout\"");
            return showError(RequestError.builder()
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .message("SAML request is too old, session timeout")
                    .build(),
                    request,
                    response,
                    model);
        }

        // Retrieve condiscon from extensions (Signicat broker does not filter this
        // value out)
        Extensions extensions = authnRequest.getExtensions();

        // We expect to either find:
        // * a single 'condiscon' attribute with a JSON condiscon blob
        // * a set of simple attributes which will be combined in a condiscon
        // If we find both a 'condiscon' attribute and a set of simple attributes, we
        // throw an error.
        // Note that optional attributes are considered mandatory
        String packedCondiscon = null;
        Map<String, Set<String>> simpleAttributes = new TreeMap<>();

        if (extensions != null) {
            List<Attribute> xmlAttributes = new ArrayList<>();
            List<XMLObject> extensionsList = extensions.getOrderedChildren();
            if (extensionsList != null) {
                for (XMLObject extension : extensionsList) {
                    if (extension instanceof RequestedAttributes) {
                        xmlAttributes.addAll(((RequestedAttributes) extension).getRequestedAttributes());
                    } else if (extension instanceof Attribute) {
                        xmlAttributes.add((Attribute) extension);
                    }
                }
            }

            // We parse all XML attributes that we found and try to fill either
            // packedCondiscon or simpleAttributes.
            // * if the 'Name' tag contains an attribute identifier and the
            // RequestedAttributes extension is used,
            // then we add that attribute identifier to the list of simpleAttributes;
            // * if the 'Name' tag contains 'condiscon' (i.e. 'signicat:param:condiscon'),
            // then we expect the XML
            // attribute values (the XML body) to contain a JSON condiscon blob for
            // packedCondiscon.
            for (Attribute xmlAttribute : xmlAttributes) {
                String attributeName = xmlAttribute.getName();
                if (attributeName.split("\\.").length == 4) {
                    if (xmlAttribute instanceof RequestedAttribute) {
                        String credentialName = attributeName.substring(0, attributeName.lastIndexOf("."));
                        Set<String> list = simpleAttributes.computeIfAbsent(credentialName, k -> new TreeSet<>());
                        if (list.contains(attributeName)) {
                            log.warn(
                                    "action=\"request-flow\", warning=\"Cannot request the same irma attribute identifier multiple times\"");
                            return showError(RequestError.builder()
                                    .statusCode(HttpStatus.BAD_REQUEST.value())
                                    .message("Cannot request the same irma attribute identifier multiple times")
                                    .build(),
                                    request,
                                    response,
                                    model);
                        }
                        list.add(attributeName);
                    } else {
                        log.warn(
                                "action=\"requestservlet.doget\", warning=\"Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension\"");
                        return showError(RequestError.builder()
                                .statusCode(HttpStatus.BAD_REQUEST.value())
                                .message(
                                        "Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension")
                                .build(),
                                request,
                                response,
                                model);
                    }
                } else if (attributeName.contains("condiscon")) {
                    for (XMLObject attributeValue : xmlAttribute.getAttributeValues()) {
                        if (packedCondiscon != null) {
                            log.warn("action=\"request-flow\", warning=\"Cannot request for multiple condiscons\"");
                            return showError(RequestError.builder()
                                    .statusCode(HttpStatus.BAD_REQUEST.value())
                                    .message("Cannot request for multiple condiscons")
                                    .build(),
                                    request,
                                    response,
                                    model);
                        }
                        try {
                            XSStringImpl attributeValueAny = (XSStringImpl) attributeValue;
                            packedCondiscon = attributeValueAny.getValue();
                        } catch (ClassCastException _e) {
                            // No-op, ignore
                        }
                    }
                } else {
                    log.warn("action=\"request-flow\", warning=\"Requested XML attribute name is invalid\"");
                    return showError(RequestError.builder()
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .message("Requested XML attribute name is invalid")
                            .build(),
                            request,
                            response,
                            model);
                }
            }
        }

        String[][][] condiscon = null;
        if (!simpleAttributes.isEmpty()) {
            if (packedCondiscon != null) {
                log.warn(
                        "action=\"request-flow\", warning=\"Cannot mix the condiscon and the requested attributes extension\"");
                return showError(RequestError.builder()
                        .statusCode(HttpStatus.BAD_REQUEST.value())
                        .message("Cannot mix the condiscon and the requested attributes extension")
                        .build(),
                        request,
                        response,
                        model);
            }
            condiscon = new String[simpleAttributes.size()][][];
            int i = 0;
            for (Set<String> attributes : simpleAttributes.values()) {
                condiscon[i++] = new String[][] { attributes.toArray(new String[0]) };
            }
        } else if (StringUtils.isNotEmpty(packedCondiscon)) {
            try {
                condiscon = objectMapper.readValue(packedCondiscon, String[][][].class);
            } catch (JsonProcessingException e) {
                log.warn("action=\"request-flow\", warning=\"Requested condiscon could not be parsed\"", e);
                return showError(RequestError.builder()
                        .statusCode(HttpStatus.BAD_REQUEST.value())
                        .message("Requested condiscon could not be parsed")
                        .build(),
                        request,
                        response,
                        model);
            }
        } else {
            // We absolutely need a decision concerning the attributeType. If none of the
            // request extensions specifies
            // IRMA attribute types, we first check the nameIdPolicy for a condiscon (legacy
            // feature). If this is
            // also not specified, the default from the configuration is used.
            NameIDPolicy nameIdPolicy = authnRequest.getNameIDPolicy();
            if (nameIdPolicy != null) {
                String nameIdPolicyFormat = nameIdPolicy.getFormat();
                if (nameIdPolicyFormat != null) {
                    try {
                        condiscon = objectMapper.readValue(nameIdPolicyFormat, String[][][].class);
                    } catch (Exception _e) {
                        log.warn("Could not convert nameIdPolicy format to a condiscons array with error: {}",
                                _e.getMessage());
                    }
                }
            }
            if (condiscon == null) {
                log.warn("action=\"request-flow\", warning=\"Requested attributeType is empty\"");
                condiscon = config.getDefaultCondiscon();
            }
        }

        String returnUrl = authnRequest.getAssertionConsumerServiceURL();
        if (StringUtils.isEmpty(returnUrl)) {
            log.debug("action=\"request-flow\", debug=\"Using default AssertionConsumerServiceURL from metadata\"");
            returnUrl = this.openSamlService.findRedirectAssertionConsumerService(entityDescriptor);
        }

        if (StringUtils.isEmpty(returnUrl)) {
            log.warn("action=\"request-flow\", warning=\"Return URL is empty (AssertionConsumerServiceURL in SAML)\"");
            return showError(RequestError.builder()
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .message("Return URL is empty (AssertionConsumerServiceURL in SAML)")
                    .build(),
                    request,
                    response,
                    model);
        }

        // Create the JWT request intended for IRMA.
        TreeMap<String, Object> content = new TreeMap<>();
        content.put("@context", "https://irma.app/ld/request/disclosure/v2");
        content.put("disclose", condiscon);

        TreeMap<String, Object> sprequest = new TreeMap<>();
        sprequest.put("request", content);
        sprequest.put("validity", 30); // Seconds that JWT session result is valid
        // sprequest.put("timeout", 240); // Seconds that JWT session is valid before it
        // times out

        // Sign with our private key
        String token = jwtUtil.createJwtToken("verification_request", "sprequest", sprequest);

        // Custom Connectis method to retrieve service provider identity.
        String spName = authnRequest.getProviderName();

        if (spName == null) {
            spName = "test";
        } else {
            spName = spName.toLowerCase();
        }

        Map<String, IrmaPath> mapping = config.getIrmaMapping();
        IrmaPath path = mapping.get(spName);

        String protocol = config.getProtocol();
        String host;
        String postfix;
        String irmaServiceHost;

        if (path == null) {
            // No specific mapping found, use generic mapping.
            host = protocol + config.getDefaultMap().getHost();
            irmaServiceHost = protocol + config.getDefaultMap().getIrmaServiceHost();
            postfix = config.getDefaultMap().getPostfix();
        } else {
            // Use specific mapping.
            host = protocol + path.getHost();
            irmaServiceHost = protocol + path.getIrmaServiceHost();
            postfix = path.getPostfix();
        }

        host = host.replace("{spName}", spName);
        postfix = postfix.replace("{spName}", spName);

        // start the IRMA session from the backend to see if it is possible to start
        // without errors
        String irmaSessionData = null;
        try {
            irmaSessionData = irmaService.startSession(token, irmaServiceHost + postfix);

            // replace the irmaServiceHost in the response back to the host, so the frontend
            // used the correct host
            irmaSessionData = irmaSessionData.replace(irmaServiceHost, host);
        } catch (BridgeException e) {
            // looging already done in the irmaService
            return showError(RequestError.builder()
                    .statusCode(e.getHttpStatusCode())
                    .message(e.getMessage())
                    .build(),
                    request,
                    response,
                    model);
        }

        // The frontend has no support for switching languages in the middle of a
        // session. Therefore, we hardcode the language for now.
        // TODO: Check whether Signicat gives us a language to use. Otherwise, add
        // support in irma-web to switch language manually.
        String language = "nl";

        request.setAttribute("irma_server", host + postfix);
        request.setAttribute("language", language);
        request.setAttribute("session_data", irmaSessionData);
        request.setAttribute("assert_url", ourPostfix + "/assert");

        String issuer = authnRequest.getIssuer().getValue();

        String repackedCondiscon = objectMapper.writeValueAsString(condiscon);

        // Create the JWT parameters used by this daemon to formulate a SAML Assertion.
        AssertParameters assertParameters = AssertParameters.builder()
                .spName(spName)
                .requestId(authnRequest.getID())
                .serviceUrl(returnUrl)
                .issuer(issuer)
                .condiscon(repackedCondiscon)
                .relayState(request.getParameter("RelayState"))
                .build();

        request.setAttribute("assert_parameters",
                jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));
        // The user browser is going to communicate with our IRMA server,
        // which is under the guise of a client hostname.
        // As such we need to give permission to perform an AJAX request to that
        // hostname.
        response.setHeader("Access-Control-Allow-Origin", host);

        response.setContentType("text/html");

        model.addAttribute("request", request);

        return "irma-request";
    }
}
