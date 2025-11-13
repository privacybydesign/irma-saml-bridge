package nl.sidn.irma.saml_bridge.util;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;

import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for BaseSAMLSimpleSignatureSecurityHandler and
 * SAML2HTTPRedirectDeflateSignatureSecurityHandler.
 */
@ExtendWith(MockitoExtension.class)
class SAML2HTTPRedirectDeflateSignatureSecurityHandlerTest {

    @Mock
    private HttpServletRequest request;
    @Mock
    private MessageContext messageContext;

    private SAMLPeerEntityContext peerCtx;
    private SAMLProtocolContext protocolCtx;

    @Mock
    private SignatureValidationParameters sigValidationParams;
    @Mock
    private SignatureTrustEngine trustEngine;

    private SAML2HTTPRedirectDeflateSignatureSecurityHandler handler;

    @BeforeEach
    void setUp() {
        handler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();

        handler.setHttpServletRequestSupplier(() -> request);

        peerCtx = new SAMLPeerEntityContext();
        protocolCtx = new SAMLProtocolContext();

        peerCtx.setRole(org.opensaml.saml.saml2.metadata.SPSSODescriptor.DEFAULT_ELEMENT_NAME); // any non-null role
        protocolCtx.setProtocol(org.opensaml.saml.common.xml.SAMLConstants.SAML20P_NS);
    }

    @Test
    void initialize_withoutRequestSupplier_throws() {
        final SAML2HTTPRedirectDeflateSignatureSecurityHandler saml2HTTPRedirectDeflateSignatureSecurityHandler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
        assertThrows(ComponentInitializationException.class, saml2HTTPRedirectDeflateSignatureSecurityHandler::initialize);
    }

    @Test
    void initialize_withRequestSupplier_ok() {
        assertDoesNotThrow(() -> handler.initialize());
    }

    @Test
    void invoke_missingPeerContextRole_throws() throws Exception {
        peerCtx.setRole(null);

        handler.initialize();

        final MessageHandlerException ex = assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
        assertTrue(ex.getMessage().contains("SAMLPeerEntityContext"));
    }

    @Test
    void invoke_missingProtocol_throws() throws Exception {
        when(messageContext.getSubcontext(eq(SAMLPeerEntityContext.class))).thenReturn(peerCtx);
        protocolCtx.setProtocol(null);

        handler.initialize();

        final MessageHandlerException ex = assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
        assertTrue(ex.getMessage().contains("SAMLProtocolContext"));
    }

    @Test
    void invoke_missingTrustEngine_throws() throws Exception {
        when(messageContext.getSubcontext(eq(SAMLPeerEntityContext.class))).thenReturn(peerCtx);
        when(messageContext.getSubcontext(eq(SAMLProtocolContext.class))).thenReturn(protocolCtx);

        handler.initialize();

        final MessageHandlerException ex = assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
        assertTrue(ex.getMessage().contains("SignatureTrustEngine"));
    }

    @Test
    void invoke_invalidBase64Signature_throws() throws Exception {
        handler.initialize();

        assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
        verifyNoInteractions(trustEngine);
    }

    @Test
    void signedContent_missingBothRequestAndResponse_throws() throws Exception {
        handler.initialize();
        peerCtx.setEntityId("any");

        assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
        verifyNoInteractions(trustEngine);
    }

    @Nested
    class SAML2HTTPRedirectDeflateSignatureSecurityHandlerTestDoPreInvokeNest {
        @BeforeEach
        void setup() {
            final SecurityParametersContext secParamsCtx = mock(SecurityParametersContext.class);

            when(messageContext.getSubcontext(eq(SAMLPeerEntityContext.class))).thenReturn(peerCtx);
            when(messageContext.getSubcontext(eq(SAMLProtocolContext.class))).thenReturn(protocolCtx);
            when(messageContext.getSubcontext(eq(SecurityParametersContext.class))).thenReturn(secParamsCtx);
            when(secParamsCtx.getSignatureValidationParameters()).thenReturn(sigValidationParams);
            when(sigValidationParams.getSignatureTrustEngine()).thenReturn(trustEngine);
        }

        @Test
        void invoke_nonGET_request_isSkipped() throws Exception {
            when(request.getMethod()).thenReturn("POST");   // ruleHandles == false

            handler.initialize();

            assertDoesNotThrow(() -> handler.invoke(messageContext));
            verifyNoInteractions(trustEngine); // validate should never be called
        }

        @Test
        void invoke_noSignatureParam_isSkippedQuietly() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(null); // missing signature
            handler.initialize();

            assertDoesNotThrow(() -> handler.invoke(messageContext));
            verifyNoInteractions(trustEngine);
        }

        @Test
        void invoke_withSignatureButNoSigAlg_isSkippedQuietly() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn(null); // missing

            handler.initialize();

            assertDoesNotThrow(() -> handler.invoke(messageContext));
            verifyNoInteractions(trustEngine);
        }

        @Test
        void signedContent_mustContainSAMLRequestOptionalRelayStateAndSigAlg_inThatOrder() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            // Inputs
            final String encodedRequest = "PHNhbWw+PC9zYW1sPg=="; // any base64 string; not used cryptographically here
            final String relay = "relay%2Bvalue"; // raw percent-encoded "+"
            final String sigAlgRaw = "http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";

            // IMPORTANT: The handler uses the *raw* query string, not decoded parameter values.
            final String rawQuery = "SAMLRequest=" + encodedRequest + "&RelayState=" + relay + "&SigAlg=" + sigAlgRaw + "&foo=bar";
            when(request.getQueryString()).thenReturn(rawQuery);

            // Signature and SigAlg present (SigAlg value must be readable from request.getParameter("SigAlg"))
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

            // Allow ruleHandles
            handler.initialize();

            // Prepare trustEngine.validate to succeed and capture the "signedContent" bytes:
            final ArgumentCaptor<byte[]> signatureCaptor = ArgumentCaptor.forClass(byte[].class);
            final ArgumentCaptor<byte[]> signedContentCaptor = ArgumentCaptor.forClass(byte[].class);
            when(trustEngine.validate(signatureCaptor.capture(), signedContentCaptor.capture(), anyString(), any(), isNull())).thenReturn(true);

            // peer entity available -> context path
            peerCtx.setEntityId("https://sp.example");

            // Invoke
            assertDoesNotThrow(() -> handler.invoke(messageContext));

            final String signedContent = new String(signedContentCaptor.getValue(), StandardCharsets.UTF_8);
            assertEquals("SAMLRequest=" + encodedRequest + "&RelayState=" + relay + "&SigAlg=" + sigAlgRaw, signedContent);
            assertTrue(peerCtx.isAuthenticated(), "Peer should be marked authenticated on successful validation");
        }


        @Test
        void validate_success_withContextEntity_authenticates() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn("algo");
            // Minimal raw query containing SAMLRequest and SigAlg in raw form:
            when(request.getQueryString()).thenReturn("SAMLRequest=req&SigAlg=algo");

            // Context entity present -> first branch
            peerCtx.setEntityId("https://issuer/context");

            when(trustEngine.validate(any(), any(), anyString(), any(), isNull())).thenReturn(true);

            handler.initialize();
            assertDoesNotThrow(() -> handler.invoke(messageContext));
            assertTrue(peerCtx.isAuthenticated());
        }

        @Test
        void validate_success_withDerivedEntity_whenContextMissing_authenticatesAndSetsEntity() throws Exception {
            final DerivedHandler subclass = new DerivedHandler(() -> request, List.of(mock(Credential.class)));

            // Request
            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn("algo");
            when(request.getQueryString()).thenReturn("SAMLRequest=req&SigAlg=algo");

            // No context entity ID -> forces derived path
            peerCtx.setEntityId(null);

            // Engine will return true when any candidate credential is supplied
            when(trustEngine.validate(any(), any(), anyString(), any(), any(Credential.class))).thenReturn(true);

            subclass.initialize();
            assertDoesNotThrow(() -> subclass.invoke(messageContext));

            assertTrue(peerCtx.isAuthenticated());
            assertEquals("https://derived.example/issuer", peerCtx.getEntityId(), "Peer entityId should be set from derived value");
        }

        @Test
        void validate_failure_throws() throws Exception {
            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn("algo");
            when(request.getQueryString()).thenReturn("SAMLRequest=req&SigAlg=algo");

            peerCtx.setEntityId("https://issuer/context");

            when(trustEngine.validate(any(), any(), anyString(), any(), isNull())).thenReturn(false);

            handler.initialize();
            final MessageHandlerException messageHandlerException = assertThrows(MessageHandlerException.class, () -> handler.invoke(messageContext));
            assertTrue(messageHandlerException.getMessage().contains("Validation of request simple signature failed"), "Should report signature failure");
            assertFalse(peerCtx.isAuthenticated());
        }


        @Test
        void validate_success_withRequestDerivedCredential() throws Exception {
            // Subclass to inject a request-derived credential (non-empty list)
            final Credential cred = mock(Credential.class);
            final DerivedHandler subclass = new DerivedHandler(() -> request, List.of(cred));

            when(request.getMethod()).thenReturn("GET");
            when(request.getParameter("Signature")).thenReturn(java.util.Base64.getEncoder().encodeToString("sig".getBytes(StandardCharsets.UTF_8)));
            when(request.getParameter("SigAlg")).thenReturn("algo");
            when(request.getQueryString()).thenReturn("SAMLRequest=req&SigAlg=algo");

            // Peer has context entity
            peerCtx.setEntityId("ctx-issuer");

            // Only succeeds when a credential is provided
            when(trustEngine.validate(any(), any(), anyString(), any(), eq(cred))).thenReturn(true);

            subclass.initialize();
            assertDoesNotThrow(() -> subclass.invoke(messageContext));
            assertTrue(peerCtx.isAuthenticated());
        }

    }

    // ---------- Helper subclass used in a couple of tests ----------

    /**
     * Test subclass to expose selected extension points:
     * - deriveSignerEntityID()
     * - getRequestCredentials()
     */
    private static class DerivedHandler extends SAML2HTTPRedirectDeflateSignatureSecurityHandler {
        private final List<Credential> creds;

        DerivedHandler(final Supplier<HttpServletRequest> supplier, final List<Credential> creds) {
            this.creds = creds;
            setHttpServletRequestSupplier(supplier::get);
        }

        @Override
        protected String deriveSignerEntityID() {
            return "https://derived.example/issuer";
        }

        @Nonnull
        @Override
        protected List<Credential> getRequestCredentials() {
            return creds == null ? Collections.emptyList() : creds;
        }
    }
}
