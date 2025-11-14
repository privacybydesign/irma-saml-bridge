package nl.sidn.irma.saml_bridge.util;

import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;
import net.shibboleth.utilities.java.support.collection.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for HTTPRedirectDeflateEncoder.
 */
class HTTPRedirectDeflateEncoderTest {

    private final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    private HTTPRedirectDeflateEncoder encoder;

    @BeforeAll
    static void bootstrapOpenSAML() throws Exception {
        // Initializes algorithm registry, parser pools, etc.
        InitializationService.initialize();
    }


    @BeforeEach
    void setUp() {
        encoder = new HTTPRedirectDeflateEncoder(response);
    }

    @Test
    void initialize_withoutMessageContext_throws() {
        assertThrows(net.shibboleth.utilities.java.support.component.ComponentInitializationException.class, () -> encoder.initialize());
    }

    @Test
    void initialize_withMessageContext_ok() {
        final MessageContext ctx = new MessageContext();
        encoder.setMessageContext(ctx);
        assertDoesNotThrow(() -> encoder.initialize());
    }

    @Test
    void destroy_marksDestroyedAndClearsContext() throws Exception {
        final MessageContext ctx = new MessageContext();
        encoder.setMessageContext(ctx);
        encoder.initialize();

        encoder.destroy();

        assertTrue(encoder.isDestroyed());
    }

    @Test
    void removeSignature_whenSigned_removesIt() {
        // Given a SignableSAMLObject that is "signed"
        final SignableStub signable = spy(new SignableStub(true));

        encoder.removeSignature(signable);

        verify(signable, times(1)).setSignature(null);
    }

    @Test
    void removeSignature_whenNotSigned_noop() {
        final SignableStub signable = spy(new SignableStub(false));

        encoder.removeSignature(signable);

        verify(signable, never()).setSignature(null);
    }

    @Test
    void removeDisallowedQueryParams_filtersOutReservedOnes() {
        final List<Pair<String, String>> params = new LinkedList<>();
        params.add(new Pair<>("SAMLRequest", "x"));
        params.add(new Pair<>("SAMLResponse", "y"));
        params.add(new Pair<>("RelayState", "r"));
        params.add(new Pair<>("SigAlg", "a"));
        params.add(new Pair<>("Signature", "s"));
        params.add(new Pair<>("foo", "1"));
        params.add(new Pair<>("bar", "2"));

        encoder.removeDisallowedQueryParams(params);

        // Only the allowed ones should remain (foo, bar)
        assertEquals(2, params.size());
        assertTrue(params.stream().anyMatch(p -> {
            assertNotNull(p.getFirst());
            if (!p.getFirst().equals("foo")) return false;
            assertNotNull(p.getSecond());
            return p.getSecond().equals("1");
        }));
        assertTrue(params.stream().anyMatch(p -> {
            assertNotNull(p.getFirst());
            if (!p.getFirst().equals("bar")) return false;
            assertNotNull(p.getSecond());
            return p.getSecond().equals("2");
        }));
    }

    @Test
    void getSignatureAlgorithmURI_returnsExplicit() throws Exception {
        final SignatureSigningParameters params = new SignatureSigningParameters();
        params.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        final String alg = encoder.getSignatureAlgorithmURI(params);
        assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", alg);
    }

    @Test
    void getSignatureAlgorithmURI_missing_throws() {
        final SignatureSigningParameters params = new SignatureSigningParameters();
        assertThrows(MessageEncodingException.class, () -> encoder.getSignatureAlgorithmURI(params));
    }

    @Test
    void generateSignature_returnsBase64() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final BasicCredential signingCredential = new BasicCredential(keyPair.getPublic(), keyPair.getPrivate());

        final String algorithmURI = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
        final String b64 = encoder.generateSignature(signingCredential, algorithmURI, "SAMLRequest=abc&SigAlg=" + algorithmURI);

        assertNotNull(b64);
        assertFalse(b64.isEmpty());
        assertTrue(b64.matches("^[A-Za-z0-9+/=]+$"));
    }

    @Test
    void buildRedirectURL_request_noSigning_preservesOriginalParamsAtEnd() throws Exception {
        final MessageContext ctx = new MessageContext();
        // Add a RequestAbstractType message
        final RequestAbstractType samlRequest = mock(RequestAbstractType.class, withSettings().extraInterfaces(SAMLObject.class));
        ctx.setMessage(samlRequest);

        // Set a RelayState (small enough to be valid)
        org.opensaml.saml.common.binding.SAMLBindingSupport.setRelayState(ctx, "relay-ok");

        // No SecurityParametersContext -> no signing branch
        // Build endpoint with both allowed + disallowed query params
        final String endpoint = URI.create("https://idp.example.org/SAML2/SSO?foo=1&SAMLRequest=xx&bar=2").toString();

        final String built = encoder.buildRedirectURL(ctx, endpoint, "ENCMSG");

        // Order: SAMLRequest, RelayState (if valid), THEN original allowed params (foo, bar)
        assertTrue(built.startsWith("https://idp.example.org/SAML2/SSO?"));
        assertTrue(built.contains("SAMLRequest=ENCMSG"));
        assertTrue(built.contains("RelayState=relay-ok"));
        assertTrue(built.contains("&foo=1"));
        assertTrue(built.contains("&bar=2"));

        // Disallowed originals must be stripped
        assertFalse(built.contains("SAMLResponse=xx"));
    }

    // ---------- buildRedirectURL (no signing) : Response path ----------

    @Test
    void buildRedirectURL_response_noSigning_usesSAMLResponseParam() throws Exception {
        final MessageContext ctx = new MessageContext();
        final StatusResponseType samlResponse = mock(StatusResponseType.class, withSettings().extraInterfaces(SAMLObject.class));
        ctx.setMessage(samlResponse);

        final String endpoint = "https://sp.example.com/acs?keep=me";
        final String built = encoder.buildRedirectURL(ctx, endpoint, "ENCRESP");

        assertTrue(built.contains("SAMLResponse=ENCRESP"));
        assertTrue(built.contains("keep=me"));
        assertFalse(built.contains("SAMLRequest="));
    }

    @Test
    void buildRedirectURL_withSigning_addsSigAlgAndSignature_andOriginalParamsFirst() throws Exception {
        // Context with a Request message
        final MessageContext ctx = new MessageContext();
        final RequestAbstractType samlRequest = mock(RequestAbstractType.class, withSettings().extraInterfaces(SAMLObject.class));
        ctx.setMessage(samlRequest);

        // Add security params for signing
        final SecurityParametersContext spc = ctx.getSubcontext(SecurityParametersContext.class, true);
        final SignatureSigningParameters signingParams = new SignatureSigningParameters();

        final KeyPair kp = generateKeyPair();
        final BasicCredential cred = new BasicCredential(kp.getPublic(), kp.getPrivate());
        signingParams.setSigningCredential(cred);
        signingParams.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        assertNotNull(spc);
        spc.setSignatureSigningParameters(signingParams);

        // Endpoint with original allowed params a=1,b=2 (should end up FIRST in the final query, in order)
        final String endpoint = "https://idp.example.org/SAML2/SSO?a=1&b=2";
        final String built = encoder.buildRedirectURL(ctx, endpoint, "ENCMSG");

        // Original params must appear BEFORE SAMLRequest/RelayState/SigAlg/Signature (due to 'addFirst' behavior)
        // So the query should start with "a=1&b=2&..."
        final String query = built.substring(built.indexOf('?') + 1);
        assertTrue(query.startsWith("a=1&b=2&"));

        assertTrue(built.contains("SAMLRequest=ENCMSG"));
        assertTrue(built.contains("SigAlg=http"));
        assertTrue(built.contains("Signature="));
    }


    @Test
    void encode_happyPath_setsHeadersAndRedirects() throws Exception {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final HTTPRedirectDeflateEncoder spyEncoder = spy(new HTTPRedirectDeflateEncoder(response));

        // MessageContext with outbound SAMLObject (request is fine)
        final MessageContext ctx = new MessageContext();
        final SAMLObject outbound = mock(RequestAbstractType.class, withSettings().extraInterfaces(SAMLObject.class));
        ctx.setMessage(outbound);

        // Populate the endpoint so SAMLBindingSupport.getEndpointURL(ctx) resolves WITHOUT static mocking
        final SAMLPeerEntityContext peer = ctx.getSubcontext(SAMLPeerEntityContext.class, true);
        assertNotNull(peer);
        final SAMLEndpointContext epCtx = peer.getSubcontext(SAMLEndpointContext.class, true);
        final Endpoint endpoint = mock(Endpoint.class);
        when(endpoint.getLocation()).thenReturn("https://idp.example.org/SAML2/SSO");
        assertNotNull(epCtx);
        epCtx.setEndpoint(endpoint);

        spyEncoder.setMessageContext(ctx);

        // Stub the heavy internals to keep this a unit test
        doNothing().when(spyEncoder).removeSignature(any(SAMLObject.class));
        doReturn("ENCODED").when(spyEncoder).deflateAndBase64Encode(any(SAMLObject.class));
        doReturn("https://idp.example.org/SAML2/SSO?SAMLRequest=ENCODED").when(spyEncoder).buildRedirectURL(eq(ctx), eq("https://idp.example.org/SAML2/SSO"), eq("ENCODED"));

        // Act
        spyEncoder.encode();

        // Verify flow + headers + redirect
        verify(spyEncoder).removeSignature(same(outbound));
        verify(spyEncoder).deflateAndBase64Encode(same(outbound));
        verify(spyEncoder).buildRedirectURL(eq(ctx), eq("https://idp.example.org/SAML2/SSO"), eq("ENCODED"));

        verify(response).setHeader("Cache-control", "no-cache, no-store");
        verify(response).setHeader("Pragma", "no-cache");
        verify(response).setCharacterEncoding("UTF-8");
        verify(response).sendRedirect("https://idp.example.org/SAML2/SSO?SAMLRequest=ENCODED");
    }

    @Test
    void encode_throwsWhenOutboundNotSAMLObject() {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder(response);

        final MessageContext ctx = new MessageContext();
        ctx.setMessage(new Object()); // not a SAMLObject
        encoder.setMessageContext(ctx);

        final MessageEncodingException ex = assertThrows(MessageEncodingException.class, encoder::encode);
        assertTrue(ex.getMessage().contains("No outbound SAML message"));
        verifyNoInteractions(response);
    }

    @Test
    void encode_wrapsIOExceptionFromSendRedirect() throws Exception {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final HTTPRedirectDeflateEncoder spyEncoder = spy(new HTTPRedirectDeflateEncoder(response));

        final MessageContext ctx = new MessageContext();
        final SAMLObject outbound = mock(RequestAbstractType.class, withSettings().extraInterfaces(SAMLObject.class));
        ctx.setMessage(outbound);

        // Give SAMLBindingSupport a real endpoint
        final SAMLPeerEntityContext peer = ctx.getSubcontext(SAMLPeerEntityContext.class, true);
        assertNotNull(peer);
        final SAMLEndpointContext epCtx = peer.getSubcontext(SAMLEndpointContext.class, true);
        final Endpoint endpoint = mock(Endpoint.class);
        when(endpoint.getLocation()).thenReturn("https://idp.example.org/SAML2/SSO");
        assertNotNull(epCtx);
        epCtx.setEndpoint(endpoint);

        spyEncoder.setMessageContext(ctx);

        doNothing().when(spyEncoder).removeSignature(any(SAMLObject.class));
        doReturn("ENC").when(spyEncoder).deflateAndBase64Encode(any(SAMLObject.class));
        doReturn("https://idp.example.org/SAML2/SSO?SAMLRequest=ENC").when(spyEncoder).buildRedirectURL(eq(ctx), eq("https://idp.example.org/SAML2/SSO"), eq("ENC"));

        doThrow(new java.io.IOException("boom")).when(response).sendRedirect("https://idp.example.org/SAML2/SSO?SAMLRequest=ENC");

        final MessageEncodingException ex = assertThrows(MessageEncodingException.class, spyEncoder::encode);
        assertTrue(ex.getMessage().contains("Problem sending HTTP redirect"));
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /**
     * Minimal stub for a SignableSAMLObject to test removeSignature behavior
     * without pulling full OpenSAML marshalling.
     */
    private static class SignableStub implements org.opensaml.saml.common.SignableSAMLObject {
        private boolean signed;
        private org.opensaml.xmlsec.signature.Signature signature;

        SignableStub(final boolean signed) {
            this.signed = signed;
        }

        @Override
        public boolean isSigned() {
            return signed;
        }

        @Override
        public void setSignature(final org.opensaml.xmlsec.signature.Signature newSignature) {
            this.signature = newSignature;
            this.signed = (newSignature != null);
        }

        @Override
        public org.opensaml.xmlsec.signature.Signature getSignature() {
            return signature;
        }

        @Override
        public List<org.opensaml.core.xml.XMLObject> getOrderedChildren() {
            return Collections.emptyList();
        }

        @Override
        public String getSignatureReferenceID() {
            return null;
        }

        @Override
        public void releaseChildrenDOM(final boolean propagateRelease) {
        }

        @Override
        public void releaseDOM() {
        }

        @Override
        public void releaseParentDOM(final boolean propagateRelease) {
        }

        @Nullable
        @Override
        public XMLObject resolveID(@Nonnull final String id) {
            return null;
        }

        @Nullable
        @Override
        public XMLObject resolveIDFromRoot(@Nonnull final String id) {
            return null;
        }

        @Override
        public void setDOM(final org.w3c.dom.Element element) {
        }

        @Override
        public org.w3c.dom.Element getDOM() {
            return null;
        }

        @Override
        public void setNoNamespaceSchemaLocation(final String location) {
        }

        @Override
        public void setSchemaLocation(final String location) {
        }

        @Nullable
        @Override
        public Boolean isNil() {
            return null;
        }

        @Nullable
        @Override
        public XSBooleanValue isNilXSBoolean() {
            return null;
        }

        @Override
        public void setNil(@Nullable final Boolean newNil) {
        }

        @Override
        public void setNil(@Nullable final XSBooleanValue newNil) {
        }

        @Nonnull
        @Override
        public LockableClassToInstanceMultiMap<Object> getObjectMetadata() {
            return null;
        }

        @Override
        public String getNoNamespaceSchemaLocation() {
            return null;
        }

        @Override
        public String getSchemaLocation() {
            return null;
        }

        @Nullable
        @Override
        public QName getSchemaType() {
            return null;
        }

        @Override
        public boolean hasChildren() {
            return false;
        }

        @Override
        public boolean hasParent() {
            return false;
        }

        @Override
        public void detach() {
        }

        @Override
        public org.opensaml.core.xml.XMLObject getParent() {
            return null;
        }

        @Override
        public void setParent(final org.opensaml.core.xml.XMLObject parent) {
        }

        @Nonnull
        @Override
        public IDIndex getIDIndex() {
            return null;
        }

        @Nonnull
        @Override
        public NamespaceManager getNamespaceManager() {
            return null;
        }

        @Nonnull
        @Override
        public Set<Namespace> getNamespaces() {
            return Set.of();
        }

        @Nonnull
        @Override
        public javax.xml.namespace.QName getElementQName() {
            return new javax.xml.namespace.QName("urn:test", "Stub");
        }

    }
}
