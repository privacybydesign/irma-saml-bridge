package nl.sidn.irma.saml_bridge.controller.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.util.HTTPRedirectDeflateEncoder;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.ext.reqattr.impl.RequestedAttributesImpl;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.impl.RequestedAttributeImpl;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;

/**
 * Starts a SAML Authentication Request and immediately redirects the browser to
 * the SAML bridge.
 * Used for integration tests and performance tests.
 */
@Slf4j
@Controller
@RequestMapping("/test/request")
public class RequestTestController {

    private final ObjectMapper objectMapper;

    private final ConfigurationService configurationService;

    private final KeyService keyService;

    public RequestTestController(
            final ObjectMapper objectMapper,
            final ConfigurationService configurationService,
            final KeyService keyService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
        this.keyService = keyService;
    }

    @GetMapping(value = "")
    public void testRequest(
            final HttpServletRequest request,
            final HttpServletResponse response) throws IOException {
        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AuthnRequestImpl> authnRequestBuilder = (SAMLObjectBuilder<AuthnRequestImpl>) factory
                .getBuilder(AuthnRequestImpl.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<IssuerImpl> issuerBuilder = (SAMLObjectBuilder<IssuerImpl>) factory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) factory
                .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<NameIDPolicyImpl> nameIDPolicyBuilder = (SAMLObjectBuilder<NameIDPolicyImpl>) factory
                .getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AttributeImpl> attributeBuilder = (SAMLObjectBuilder<AttributeImpl>) factory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        final XSStringBuilder attributeValueBuilder = (XSStringBuilder) factory.getBuilder(XSString.TYPE_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<ExtensionsImpl> extensionsBuilder = (SAMLObjectBuilder<ExtensionsImpl>) factory
                .getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<RequestedAttributesImpl> requestedAttributesBuilder = (SAMLObjectBuilder<RequestedAttributesImpl>) factory
                .getBuilder(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<RequestedAttributeImpl> requestedAttributeBuilder = (SAMLObjectBuilder<RequestedAttributeImpl>) factory
                .getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME);

        final AuthnRequestImpl authnRequest = authnRequestBuilder.buildObject();

        final IssuerImpl issuer = issuerBuilder.buildObject();

        if (request.getParameter("fake-issuer") == null) {
            issuer.setValue(this.configurationService.getConfiguration().getIssuerName());
        } else {
            issuer.setValue("i-am-fake-issuer");
        }

        Instant now = Instant.now();
        if (request.getParameter("old-request") != null) {
            now = now.minusSeconds(86400);
        }

        authnRequest.setIssueInstant(now);

        final String protocol = configurationService.getConfiguration().getProtocol();
        final String hostname = this.configurationService.getConfiguration().getHost();
        final String path = protocol + hostname;

        authnRequest.setIssuer(issuer);

        final String packedRequest = request.getParameter("request");
        String mode = request.getParameter("mode");

        if (mode == null) {
            mode = "attributes";
        }

        if (packedRequest != null) {
            switch (mode) {
                case "attributes": {
                    final String[] attributes = objectMapper.readValue(packedRequest, String[].class);

                    if (attributes.length == 0) {
                        response.setStatus(401);
                        response.getWriter().write(
                                "When using 'attributes' mode, please provide a list with attributes, i.e. [\"attribute\"].");
                        return;
                    }

                    final Extensions extensions = extensionsBuilder.buildObject();
                    final RequestedAttributesImpl requestedAttributes = requestedAttributesBuilder.buildObject();

                    for (final String key : attributes) {
                        final RequestedAttributeImpl requestedAttribute = requestedAttributeBuilder.buildObject();
                        requestedAttribute.setIsRequired(true);
                        requestedAttribute.setName(key);
                        requestedAttributes.getRequestedAttributes().add(requestedAttribute);
                    }

                    extensions.getUnknownXMLObjects().add(requestedAttributes);
                    authnRequest.setExtensions(extensions);
                    break;
                }
                case "condiscon-signicat":
                case "condiscon": {
                    final RequestedAttributeImpl requestedAttribute = requestedAttributeBuilder.buildObject();
                    requestedAttribute.setName(mode.equals("condiscon") ? mode : "signicat:param:condiscon");

                    final XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME);
                    attributeValue.setValue(packedRequest);

                    requestedAttribute.getAttributeValues().add(attributeValue);

                    final Extensions extensions = extensionsBuilder.buildObject();

                    final RequestedAttributesImpl requestedAttributes = requestedAttributesBuilder.buildObject();
                    requestedAttributes.getRequestedAttributes().add(requestedAttribute);

                    extensions.getUnknownXMLObjects().add(requestedAttributes);
                    authnRequest.setExtensions(extensions);
                    break;
                }
                case "condiscon-nameid": {
                    final NameIDPolicyImpl nameIDPolicy = nameIDPolicyBuilder.buildObject();
                    nameIDPolicy.setFormat(packedRequest);

                    authnRequest.setNameIDPolicy(nameIDPolicy);
                    break;
                }
                case "condiscon-attribute": {
                    final Attribute attribute = attributeBuilder.buildObject();
                    attribute.setName("condiscon");

                    final XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME);
                    attributeValue.setValue(packedRequest);

                    attribute.getAttributeValues().add(attributeValue);

                    final Extensions extensions = extensionsBuilder.buildObject();
                    extensions.getUnknownXMLObjects().add(attribute);

                    authnRequest.setExtensions(extensions);
                    break;
                }
                default: {
                    log.warn("action=\"requesttestcontroller\", error=\"Unknown request mode\"");
                    response.setStatus(400);
                    return;
                }
            }
        }

        final MessageContext messageContext = new MessageContext();
        messageContext.setMessage(authnRequest);

        // TODO use separate credential for testing?
        final Credential credential = new BasicX509Credential(
                this.keyService.getSamlCertificate(),
                this.keyService.getSamlPrivateKey());

        final SignatureSigningParameters sigparams = new SignatureSigningParameters();
        sigparams.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        sigparams.setSigningCredential(credential);

        final SecurityParametersContext secparamContext = messageContext.getSubcontext(SecurityParametersContext.class, true);
        secparamContext.setSignatureSigningParameters(sigparams);

        final Endpoint samlEndpoint = endpointBuilder.buildObject();
        samlEndpoint.setLocation(String.format("%s%s/request",
                path,
                this.configurationService.getConfiguration().getPostfix()));

        final SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        final SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(samlEndpoint);

        final HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder(response);
        encoder.setMessageContext(messageContext);
        try {
            encoder.initialize();
        } catch (final ComponentInitializationException e) {
            log.error(e.getMessage(), e);
            return;
        }

        try {
            encoder.encode();
            System.out.println("Redirecting to SAML Bridge...");
        } catch (final MessageEncodingException e) {
            log.error(e.getMessage(), e);
        }
    }
}
