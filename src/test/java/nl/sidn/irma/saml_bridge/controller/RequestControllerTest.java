package nl.sidn.irma.saml_bridge.controller;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.model.IrmaPath;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.IrmaService;
import nl.sidn.irma.saml_bridge.service.OpenSamlService;
import nl.sidn.irma.saml_bridge.service.SignatureValidationService;
import nl.sidn.irma.saml_bridge.util.HTTPRedirectDeflateDecoder;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.ext.reqattr.RequestedAttributes;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.TreeMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = RequestController.class)
@AutoConfigureMockMvc
class RequestControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    SignatureValidationService signatureValidationService;
    @MockitoBean
    ConfigurationService configurationService;
    @MockitoBean
    OpenSamlService openSamlService;
    @MockitoBean
    JwtUtil jwtUtil;
    @MockitoBean
    IrmaService irmaService;
    @MockitoBean
    HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder;


    @BeforeAll
    static void initOpenSAML() {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new RuntimeException("OpenSAML init failed", e);
        }
    }

    // ---------- Helpers ----------

    @SuppressWarnings("unchecked")
    private static <T extends XMLObject> T build(final QName qname) {
        return (T) XMLObjectSupport.buildXMLObject(qname);
    }

    private static AuthnRequest buildAuthnRequest(final Instant issueInstant) {
        final AuthnRequest req = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
        req.setID("_" + java.util.UUID.randomUUID());
        req.setIssueInstant(issueInstant);
        req.setVersion(org.opensaml.saml.common.SAMLVersion.VERSION_20);
        req.setAssertionConsumerServiceURL("https://sp.example.com/acs");

        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://sp.example.com/metadata");
        req.setIssuer(issuer);

        req.setProviderName("MySP");

        final Extensions exts = build(Extensions.DEFAULT_ELEMENT_NAME);
        final RequestedAttributes requestedAttributes = (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);

        final RequestedAttribute requestedAttribute = (RequestedAttribute) XMLObjectSupport.buildXMLObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        requestedAttribute.setName("irma-demo.mijnoverheid.fullname.value"); // 4-part name expected by controller
        requestedAttributes.getRequestedAttributes().add(requestedAttribute);

        exts.getUnknownXMLObjects().add(requestedAttributes);
        req.setExtensions(exts);

        return req;
    }

    private static String marshallToString(final XMLObject xmlObject) throws MarshallingException {
        final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        final Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        if (marshaller == null) {
            throw new MarshallingException("No marshaller registered for " + xmlObject.getElementQName());
        }

        final Element element = marshaller.marshall(xmlObject);

        try {
            final TransformerFactory tf = TransformerFactory.newInstance();
            final Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");

            final StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            return writer.toString();
        } catch (final TransformerException e) {
            throw new MarshallingException("Error converting DOM to String", e);
        }
    }

    private static String toRedirectSAMLRequestParam(final XMLObject xmlObject) throws Exception {
        final String xml = marshallToString(xmlObject);

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (final DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, new Deflater(Deflater.DEFLATED, true))) {
            deflaterOutputStream.write(xml.getBytes(StandardCharsets.UTF_8));
        }

        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    private void stubCommonConfig(final AuthnRequest authnRequest) throws BridgeException, ComponentInitializationException, ResolverException, MessageHandlerException {

        final Configuration cfg = mock(Configuration.class);
        final IrmaPath defaultMap = mock(IrmaPath.class);

        final MessageContext messageContext = new MessageContext();
        messageContext.setMessage(authnRequest);

        // Used in controller:
        given(cfg.getPostfix()).willReturn("/irma-saml-bridge");
        given(cfg.getRequestTtlInSec()).willReturn(300);
        given(cfg.getIrmaMapping()).willReturn(Collections.emptyMap());
        given(cfg.getDefaultCondiscon()).willReturn(new String[][][]{{{"irma-demo.mijnoverheid.fullname.value"}}});
        given(cfg.getProtocol()).willReturn("https://");

        given(defaultMap.getHost()).willReturn("irma.{spName}.example.org");
        given(defaultMap.getIrmaServiceHost()).willReturn("irma-api.example.org");
        given(defaultMap.getPostfix()).willReturn("/irma");
        given(cfg.getDefaultMap()).willReturn(defaultMap);

        given(configurationService.getConfiguration()).willReturn(cfg);

        given(signatureValidationService.verifySignature(any(HttpServletRequest.class), any(MessageContext.class))).willReturn(mock(EntityDescriptor.class));

        given(jwtUtil.createJwtToken(anyString(), anyString(), any(TreeMap.class))).willReturn("jwt-token");

        given(irmaService.startSession(anyString(), anyString())).willReturn("{\"sessionPtr\":{\"u\":\"dummy\"}}");

        // This is the key line: decoder now returns a context whose message IS an AuthnRequest
        given(httpRedirectDeflateDecoder.getMessageContext()).willReturn(messageContext);
    }

    // ---------- Tests ----------

    @Test
    void request_happyPath_returnsIrmaRequestView_andSetsHeadersAndAttributes() throws Exception {
        final AuthnRequest req = buildAuthnRequest(Instant.now());
        stubCommonConfig(req);

        final String samlParam = toRedirectSAMLRequestParam(req);

        mockMvc.perform(get("/request").param("SAMLRequest", samlParam).param("RelayState", "relay123")).andExpect(status().isOk()).andExpect(view().name("irma-request")).andExpect(model().attributeExists("request")).andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://irma.mysp.example.org"));
    }

    @Test
    void request_expiredAuthnRequest_returns400ErrorView() throws Exception {
        final AuthnRequest req = buildAuthnRequest(Instant.now().minusSeconds(10000));
        stubCommonConfig(req);

        final String samlParam = toRedirectSAMLRequestParam(req);

        mockMvc.perform(get("/request").param("SAMLRequest", samlParam)).andExpect(status().isBadRequest()).andExpect(view().name("irma-request"));
    }


    @Test
    void request_httpRedirectDeflateDecoder_initializationException() throws Exception {
        final AuthnRequest req = buildAuthnRequest(Instant.now());
        stubCommonConfig(req);


        // Simulate decoder failing because SAMLRequest is missing
        doThrow(ComponentInitializationException.class).when(httpRedirectDeflateDecoder).initialize();


        mockMvc.perform(get("/request")).andExpect(status().isInternalServerError()).andExpect(view().name("irma-request"));
    }

    @Test
    void request_httpRedirectDeflateDecoder_decodeException() throws Exception {
        final AuthnRequest req = buildAuthnRequest(Instant.now());
        stubCommonConfig(req);


        // Simulate decoder failing because SAMLRequest is missing
        doThrow(MessageDecodingException.class).when(httpRedirectDeflateDecoder).decode();


        mockMvc.perform(get("/request")).andExpect(status().isInternalServerError()).andExpect(view().name("irma-request"));
    }

    @Test
    void request_authRequestIsNull_returnsUnauthorizedResponse() throws Exception {
        stubCommonConfig(null);

        mockMvc.perform(get("/request")).andExpect(status().isBadRequest()).andExpect(view().name("irma-request"));
    }

    @Test
    void request_signatureValidationServiceVerifySignature_throwsException() throws Exception {
        final AuthnRequest req = buildAuthnRequest(Instant.now());
        stubCommonConfig(req);
        given(signatureValidationService.verifySignature(any(HttpServletRequest.class), any(MessageContext.class))).willThrow(MessageHandlerException.class);

        mockMvc.perform(get("/request")).andExpect(status().isUnauthorized());
    }
}