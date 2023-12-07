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
            ObjectMapper objectMapper,
            ConfigurationService configurationService,
            KeyService keyService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
        this.keyService = keyService;
    }

    @GetMapping(value = "")
    public void testRequest(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnRequestImpl> authnRequestBuilder = (SAMLObjectBuilder<AuthnRequestImpl>) factory
                .getBuilder(AuthnRequestImpl.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<IssuerImpl> issuerBuilder = (SAMLObjectBuilder<IssuerImpl>) factory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) factory
                .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<NameIDPolicyImpl> nameIDPolicyBuilder = (SAMLObjectBuilder<NameIDPolicyImpl>) factory
                .getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AttributeImpl> attributeBuilder = (SAMLObjectBuilder<AttributeImpl>) factory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) factory.getBuilder(XSString.TYPE_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<ExtensionsImpl> extensionsBuilder = (SAMLObjectBuilder<ExtensionsImpl>) factory
                .getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<RequestedAttributesImpl> requestedAttributesBuilder = (SAMLObjectBuilder<RequestedAttributesImpl>) factory
                .getBuilder(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<RequestedAttributeImpl> requestedAttributeBuilder = (SAMLObjectBuilder<RequestedAttributeImpl>) factory
                .getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME);

        AuthnRequestImpl authnRequest = authnRequestBuilder.buildObject();

        IssuerImpl issuer = issuerBuilder.buildObject();

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

        String protocol = configurationService.getConfiguration().getProtocol();
        String hostname = this.configurationService.getConfiguration().getHost();
        String path = protocol + hostname;

        authnRequest.setIssuer(issuer);

        String packedRequest = request.getParameter("request");
        String mode = request.getParameter("mode");

        if (mode == null) {
            mode = "attributes";
        }

        if (packedRequest != null) {
            switch (mode) {
                case "attributes": {
                    String[] attributes = objectMapper.readValue(packedRequest, String[].class);

                    if (attributes.length == 0) {
                        response.setStatus(401);
                        response.getWriter().write(
                                "When using 'attributes' mode, please provide a list with attributes, i.e. [\"attribute\"].");
                        return;
                    }

                    Extensions extensions = extensionsBuilder.buildObject();
                    RequestedAttributesImpl requestedAttributes = requestedAttributesBuilder.buildObject();

                    for (String key : attributes) {
                        RequestedAttributeImpl requestedAttribute = requestedAttributeBuilder.buildObject();
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
                    RequestedAttributeImpl requestedAttribute = requestedAttributeBuilder.buildObject();
                    requestedAttribute.setName(mode.equals("condiscon") ? mode : "signicat:param:condiscon");

                    XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME);
                    attributeValue.setValue(packedRequest);

                    requestedAttribute.getAttributeValues().add(attributeValue);

                    Extensions extensions = extensionsBuilder.buildObject();

                    RequestedAttributesImpl requestedAttributes = requestedAttributesBuilder.buildObject();
                    requestedAttributes.getRequestedAttributes().add(requestedAttribute);

                    extensions.getUnknownXMLObjects().add(requestedAttributes);
                    authnRequest.setExtensions(extensions);
                    break;
                }
                case "condiscon-nameid": {
                    NameIDPolicyImpl nameIDPolicy = nameIDPolicyBuilder.buildObject();
                    nameIDPolicy.setFormat(packedRequest);

                    authnRequest.setNameIDPolicy(nameIDPolicy);
                    break;
                }
                case "condiscon-attribute": {
                    Attribute attribute = attributeBuilder.buildObject();
                    attribute.setName("condiscon");

                    XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME);
                    attributeValue.setValue(packedRequest);

                    attribute.getAttributeValues().add(attributeValue);

                    Extensions extensions = extensionsBuilder.buildObject();
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

        MessageContext messageContext = new MessageContext();
        messageContext.setMessage(authnRequest);

        // TODO use separate credential for testing?
        Credential credential = new BasicX509Credential(
                this.keyService.getSamlCertificate(),
                this.keyService.getSamlPrivateKey());

        SignatureSigningParameters sigparams = new SignatureSigningParameters();
        sigparams.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        sigparams.setSigningCredential(credential);

        SecurityParametersContext secparamContext = messageContext.getSubcontext(SecurityParametersContext.class, true);
        secparamContext.setSignatureSigningParameters(sigparams);

        Endpoint samlEndpoint = endpointBuilder.buildObject();
        samlEndpoint.setLocation(String.format("%s%s/request",
                path,
                this.configurationService.getConfiguration().getPostfix()));

        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(samlEndpoint);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder(response);
        encoder.setMessageContext(messageContext);
        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            e.printStackTrace();
            return;
        }

        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            e.printStackTrace();
        }
    }
}
