package nl.sidn.irma.saml_bridge.service;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.primitive.NonnullSupplier;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.ChainingMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SignatureValidationService.
 */
@ExtendWith(SpringExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SignatureValidationServiceTest {

    // Deep stubs let us do configurationService.getConfiguration().getSamlMetadataPath()
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    ConfigurationService configurationService;

    @Mock
    ParserPool parserPool;

    @Mock
    HttpServletRequest httpServletRequest;

    @AfterEach
    void tearDown() {
        Mockito.framework().clearInlineMocks();
    }

    /**
     * Helper to set private fields via reflection.
     */
    private static void setField(final Object target, final String fieldName, final Object value) throws Exception {
        final Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    /**
     * Builds a temp empty directory path for metadata loading.
     */
    private static File ensureTempDir() {
        final File dir = new File(System.getProperty("java.io.tmpdir"), "saml-meta-" + System.nanoTime());
        assertTrue(dir.mkdirs() || dir.exists(), "Could not create temp metadata dir");
        return dir;
    }

    /**
     * Happy path: SignatureSecurityHandler marks the message authenticated and we have a matching metadata EntityDescriptor.
     */
    @Test
    void verifySignature_authenticated_metadataFound_returnsDescriptor() throws Exception {
        final File metaDir = ensureTempDir();
        when(configurationService.getConfiguration().getSamlMetadataPath()).thenReturn(metaDir.getAbsolutePath());

        // Mock construction of SignatureSecurityHandler so invoke() authenticates and sets an entityId
        try (final MockedConstruction<nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler> ignored =
                     Mockito.mockConstruction(nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler.class,
                             (mock, context) -> {
                                 // setHttpServletRequestSupplier/initialize are no-ops
                                 doNothing().when(mock).setHttpServletRequestSupplier(any(NonnullSupplier.class));
                                 doNothing().when(mock).initialize();
                                 doAnswer(invocation -> {
                                     final MessageContext mc = invocation.getArgument(0);
                                     // ensure subcontexts exist (the SUT also sets them)
                                     mc.getSubcontext(SAMLPeerEntityContext.class, true);
                                     Objects.requireNonNull(mc.getSubcontext(SAMLProtocolContext.class, true)).setProtocol(SAMLConstants.SAML20P_NS);
                                     Objects.requireNonNull(mc.getSubcontext(SecurityParametersContext.class, true))
                                             .setSignatureValidationParameters(new SignatureValidationParameters());

                                     final SAMLPeerEntityContext peer = mc.getSubcontext(SAMLPeerEntityContext.class);
                                     assertNotNull(peer);
                                     peer.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                                     peer.setEntityId("test-entity-id");
                                     peer.setAuthenticated(true);
                                     return null;
                                 }).when(mock).invoke(any(MessageContext.class));
                             })) {

            // Construct SUT (runs initialize())
            final SignatureValidationService sut = new SignatureValidationService(configurationService, parserPool);

            // Replace the internal metadataResolver with a mock that returns a descriptor
            final ChainingMetadataResolver mockChain = mock(ChainingMetadataResolver.class);
            final EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
            when(mockChain.resolve(any(CriteriaSet.class)))
                    .thenReturn(Collections.singletonList(mockDescriptor));
            setField(sut, "metadataResolver", mockChain);

            final MessageContext messageContext = new MessageContext();
            final EntityDescriptor result = sut.verifySignature(httpServletRequest, messageContext);

            assertSame(mockDescriptor, result, "Returned EntityDescriptor should be the one from the resolver");
            // Also sanity-check the context was populated
            assertEquals(SAMLConstants.SAML20P_NS,
                    Objects.requireNonNull(messageContext.getSubcontext(SAMLProtocolContext.class)).getProtocol());
        }
    }

    /**
     * Unauthenticated message: the handler runs but doesn't mark it authenticated → SUT should throw MessageHandlerException.
     */
    @Test
    void verifySignature_unauthenticated_throws() throws Exception {
        final File metaDir = ensureTempDir();
        when(configurationService.getConfiguration().getSamlMetadataPath()).thenReturn(metaDir.getAbsolutePath());

        try (final MockedConstruction<nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler> ignored =
                     Mockito.mockConstruction(nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler.class,
                             (mock, context) -> {
                                 doNothing().when(mock).initialize();
                                 doNothing().when(mock).setHttpServletRequestSupplier(any());
                                 doAnswer(invocation -> {
                                     MessageContext mc = invocation.getArgument(0);
                                     Objects.requireNonNull(mc.getSubcontext(SAMLPeerEntityContext.class, true)).setAuthenticated(false);
                                     return null;
                                 }).when(mock).invoke(any(MessageContext.class));
                             })) {
            final SignatureValidationService sut = new SignatureValidationService(configurationService, parserPool);

            final MessageContext messageContext = new MessageContext();
            assertThrows(MessageHandlerException.class,
                    () -> sut.verifySignature(httpServletRequest, messageContext),
                    "Expected MessageHandlerException when message is not authenticated");
        }
    }

    /**
     * Authenticated but no matching metadata → SUT should throw MessageHandlerException.
     */
    @Test
    void verifySignature_authenticated_noMetadata_throws() throws Exception {
        final File metaDir = ensureTempDir();
        when(configurationService.getConfiguration().getSamlMetadataPath()).thenReturn(metaDir.getAbsolutePath());

        try (final MockedConstruction<nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler> ignored =
                     Mockito.mockConstruction(nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler.class,
                             (mock, context) -> {
                                 doNothing().when(mock).initialize();
                                 doNothing().when(mock).setHttpServletRequestSupplier(any());
                                 doAnswer(invocation -> {
                                     MessageContext mc = invocation.getArgument(0);
                                     SAMLPeerEntityContext peer = mc.getSubcontext(SAMLPeerEntityContext.class, true);
                                     assertNotNull(peer);
                                     peer.setAuthenticated(true);
                                     peer.setEntityId("missing-entity");
                                     return null;
                                 }).when(mock).invoke(any(MessageContext.class));
                             })) {
            final SignatureValidationService sut = new SignatureValidationService(configurationService, parserPool);

            // Mock resolver to return empty iterable
            final ChainingMetadataResolver mockChain = mock(ChainingMetadataResolver.class);
            when(mockChain.resolve(any(CriteriaSet.class))).thenReturn(Collections.emptyList());
            setField(sut, "metadataResolver", mockChain);

            final MessageContext messageContext = new MessageContext();
            assertThrows(MessageHandlerException.class,
                    () -> sut.verifySignature(httpServletRequest, messageContext),
                    "Expected MessageHandlerException when no metadata matches the entityId");
        }
    }

    @Test
    void cleanup_destroysFilesystemResolvers() throws Exception {
        final File metaDir = ensureTempDir();
        when(configurationService.getConfiguration().getSamlMetadataPath()).thenReturn(metaDir.getAbsolutePath());

        try (final MockedConstruction<FilesystemMetadataResolver> ignored = Mockito.mockConstruction(FilesystemMetadataResolver.class)) {
            final SignatureValidationService sut = new SignatureValidationService(configurationService, parserPool);

            final FilesystemMetadataResolver fsMock = mock(FilesystemMetadataResolver.class);
            final ArrayList<FilesystemMetadataResolver> list = new ArrayList<>(List.of(fsMock));
            setField(sut, "resolvers", list);

            sut.cleanup();
            verify(fsMock, times(1)).destroy();
        }
    }
}
