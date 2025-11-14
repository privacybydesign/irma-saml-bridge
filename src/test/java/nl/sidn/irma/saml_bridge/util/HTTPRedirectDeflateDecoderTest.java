package nl.sidn.irma.saml_bridge.util;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link HTTPRedirectDeflateDecoder}.
 */
@ExtendWith(MockitoExtension.class)
class HTTPRedirectDeflateDecoderTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @BeforeAll
    static void initOpenSaml() throws Exception {
        // Required so that XMLObjectProviderRegistrySupport.getParserPool() etc. are initialized.
        InitializationService.initialize();
    }

    /**
     * Helper to build a minimal, valid SAML2 AuthnRequest, compress it (DEFLATE, nowrap=true),
     * and Base64 encode it as used in HTTP-Redirect binding.
     */
    private String buildEncodedRedirectAuthnRequest() throws Exception {
        final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        final AuthnRequestBuilder authnRequestBuilder =
                (AuthnRequestBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        assertNotNull(authnRequestBuilder);
        final AuthnRequest authnRequest = authnRequestBuilder.buildObject();

        // Basic required fields
        authnRequest.setID("_" + UUID.randomUUID());
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setDestination("https://idp.example.org/SAML2/SSO/Redirect");
        authnRequest.setForceAuthn(Boolean.FALSE);
        authnRequest.setIsPassive(Boolean.FALSE);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL("https://sp.example.org/acs");

        final IssuerBuilder issuerBuilder =
                (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        assertNotNull(issuerBuilder);
        final Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("https://sp.example.org/metadata");
        authnRequest.setIssuer(issuer);

        final NameIDPolicyBuilder nameIDPolicyBuilder =
                (NameIDPolicyBuilder) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        assertNotNull(nameIDPolicyBuilder);
        final NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.PERSISTENT);
        authnRequest.setNameIDPolicy(nameIDPolicy);

        final RequestedAuthnContextBuilder racBuilder =
                (RequestedAuthnContextBuilder) builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        assertNotNull(racBuilder);
        final RequestedAuthnContext requestedAuthnContext = racBuilder.buildObject();
        final AuthnContextClassRefBuilder accRefBuilder =
                (AuthnContextClassRefBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        assertNotNull(accRefBuilder);
        final AuthnContextClassRef accRef = accRefBuilder.buildObject();
        accRef.setURI(AuthnContext.PPT_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(accRef);
        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        final ScopingBuilder scopingBuilder =
                (ScopingBuilder) builderFactory.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
        assertNotNull(scopingBuilder);
        final Scoping scoping = scopingBuilder.buildObject();
        authnRequest.setScoping(scoping);

        // Marshall to DOM → String
        final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        final Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);
        assertNotNull(marshaller);
        final Element element = marshaller.marshall(authnRequest);
        final String xml = serialize(element);

        // DEFLATE (nowrap=true) and Base64 encode
        final byte[] input = xml.getBytes(StandardCharsets.UTF_8);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        try (final DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
            dos.write(input);
        }
        final byte[] deflated = baos.toByteArray();
        return Base64.getEncoder().encodeToString(deflated);
    }

    @Test
    void initialize_withoutServletRequest_throwsException() {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

        // We do NOT call setHttpServletRequest(), so it stays null
        assertThrows(ComponentInitializationException.class, decoder::initialize);
    }

    @Test
    void decode_withNonGetMethod_throwsMessageDecodingException() throws Exception {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setHttpServletRequest(httpServletRequest);
        decoder.initialize();

        when(httpServletRequest.getMethod()).thenReturn("POST");

        final MessageDecodingException ex =
                assertThrows(MessageDecodingException.class, decoder::decode);
        assertTrue(ex.getMessage().contains("only supports the HTTP GET method"));
    }

    @Test
    void decode_withUnsupportedSamlEncoding_throwsMessageDecodingException() throws Exception {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setHttpServletRequest(httpServletRequest);
        decoder.initialize();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(httpServletRequest.getParameter("SAMLEncoding")).thenReturn("urn:some:other:encoding");

        final MessageDecodingException ex =
                assertThrows(MessageDecodingException.class, decoder::decode);
        assertTrue(ex.getMessage().contains("unsupported SAMLEncoding"));
    }

    @Test
    void decode_withoutSamlRequestOrResponse_throwsMessageDecodingException() throws Exception {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setHttpServletRequest(httpServletRequest);
        decoder.initialize();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(httpServletRequest.getParameter("SAMLEncoding")).thenReturn(null);
        when(httpServletRequest.getParameter("RelayState")).thenReturn(null);
        when(httpServletRequest.getParameter("SAMLRequest")).thenReturn(null);
        when(httpServletRequest.getParameter("SAMLResponse")).thenReturn(null);

        final MessageDecodingException ex =
                assertThrows(MessageDecodingException.class, decoder::decode);
        assertTrue(ex.getMessage().contains("No SAMLRequest or SAMLResponse"));
    }

    @Test
    void decode_withValidSamlRequest_populatesMessageAndBindingContext() throws Exception {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setHttpServletRequest(httpServletRequest);
        decoder.initialize();

        final String encodedRequest = buildEncodedRedirectAuthnRequest();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(httpServletRequest.getParameter("SAMLEncoding")).thenReturn(null);
        when(httpServletRequest.getParameter("RelayState")).thenReturn("relay-state-123");
        when(httpServletRequest.getParameter("SAMLRequest")).thenReturn(encodedRequest);
        when(httpServletRequest.getParameter("Signature")).thenReturn(null); // no signature

        // Act
        decoder.decode();

        // Assert message context
        final MessageContext messageContext = decoder.getMessageContext();
        assertNotNull(messageContext);
        assertInstanceOf(AuthnRequest.class, messageContext.getMessage());

        final AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
        assertEquals(SAMLVersion.VERSION_20, authnRequest.getVersion());
        assertEquals("https://sp.example.org/metadata", authnRequest.getIssuer().getValue());

        // Assert relay state
        assertEquals("relay-state-123", SAMLBindingSupport.getRelayState(messageContext));

        // Assert binding context
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class, false);
        assertNotNull(bindingContext);
        assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, bindingContext.getBindingUri());
        assertFalse(bindingContext.hasBindingSignature());
    }

    @Test
    void decodeMessage_withInvalidBase64_throwsMessageDecodingException() {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

        final String invalidBase64 = "###notBase64###";

        final MessageDecodingException ex =
                assertThrows(MessageDecodingException.class,
                        () -> decoder.decodeMessage(invalidBase64));
        assertTrue(ex.getMessage().contains("Unable to Base64 decode and inflate SAML message"));
    }

    private static String serialize(final Element element) throws Exception {
        final TransformerFactory transformerFactory = TransformerFactory.newInstance();
        final Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        final StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.toString();
    }

}
