package nl.sidn.irma.saml_bridge.service;

import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.NonnullSupplier;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import nl.sidn.irma.saml_bridge.util.SignatureSecurityHandler;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.ChainingMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.DEREncodedKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.DSAKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.RSAKeyValueProvider;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.Objects;
import java.util.stream.StreamSupport;

/**
 * Service that reads in all metadata files, from the directory as indicated in
 * the configuration file,
 * and initializes an OpenSAML Signature Trust Engine set to use the public keys
 * listed in those metadata files.
 * <p>
 * Uses the EntityID in the metadata file and the Issuer-field from a SAML
 * Authnrequest to figure out which public
 * key is used. The public key may be in DER, DSA, RSA or X509-formats.
 */
@Service
@DependsOn("OpenSamlService")
public class SignatureValidationService {

    private final ConfigurationService configurationService;

    private final ParserPool parserPool;

    // The signature trust engine that is used to select the proper key/metadata.
    private ExplicitKeySignatureTrustEngine signatureTrustEngine;

    // The filesystem resolvers that are currently active.
    private final ArrayList<FilesystemMetadataResolver> resolvers = new ArrayList<>();

    private ChainingMetadataResolver metadataResolver;

    public SignatureValidationService(
            final ConfigurationService configurationService,
            final ParserPool parserPool) throws ResolverException, ComponentInitializationException {
        this.configurationService = configurationService;
        this.parserPool = parserPool;
        initialize();
    }

    /**
     * Initialize the signature validation service by loading the metadatafiles, and
     * initializing
     * the underlying signature trust engine.
     *
     * @throws ResolverException                The resolver exception.
     * @throws ComponentInitializationException The component initialization exception.
     */
    private void initialize() throws ResolverException, ComponentInitializationException {
        // TODO properly reload trust engine periodically

        final File directory = new File(this.configurationService.getConfiguration().getSamlMetadataPath());

        for (final File metadata : Objects.requireNonNull(directory.listFiles())) {
            final FilesystemMetadataResolver fs = new FilesystemMetadataResolver(metadata);
            fs.setId("fs-metadataresolver-" + metadata.getName());
            fs.setParserPool(parserPool);
            fs.initialize();

            this.resolvers.add(fs);
        }

        this.metadataResolver = new ChainingMetadataResolver();
        this.metadataResolver.setId("chaining-metadataresolver");
        this.metadataResolver.setResolvers(this.resolvers);
        this.metadataResolver.initialize();

        final ArrayList<KeyInfoProvider> kips = new ArrayList<>();
        kips.add(new DEREncodedKeyValueProvider());
        kips.add(new DSAKeyValueProvider());
        kips.add(new RSAKeyValueProvider());
        kips.add(new InlineX509DataProvider());

        final BasicProviderKeyInfoCredentialResolver kicr = new BasicProviderKeyInfoCredentialResolver(kips);

        final PredicateRoleDescriptorResolver rd = new PredicateRoleDescriptorResolver(this.metadataResolver);
        rd.initialize();

        final MetadataCredentialResolver resolver = new MetadataCredentialResolver();
        resolver.setKeyInfoCredentialResolver(kicr);
        resolver.setRoleDescriptorResolver(rd);
        resolver.initialize();

        this.signatureTrustEngine = new ExplicitKeySignatureTrustEngine(
                resolver,
                kicr);
    }

    /**
     * Destroy all underlying metadata resolvers, cleaning up their resources such
     * as timers and threads.
     */
    @PreDestroy
    public void cleanup() {
        for (final FilesystemMetadataResolver resolver : this.resolvers) {
            resolver.destroy();
        }
    }

    /**
     * Check the signature on the SAML2 HTTP message.
     * <p>
     * Suppress warning due to message context invocation when type parameter is not
     * known upstream.
     *
     * @param request        The HTTP servlet request.
     * @param messageContext The message context.
     * @return The entity descriptor of the signer.
     * @throws ComponentInitializationException Component initialization exception.
     * @throws MessageHandlerException          Message handler exception.
     * @throws ResolverException                Resolver exception.
     */
    public EntityDescriptor verifySignature(final HttpServletRequest request, final MessageContext messageContext)
            throws ComponentInitializationException, MessageHandlerException, ResolverException {
        final SignatureValidationParameters sigValParams = new SignatureValidationParameters();
        sigValParams.setSignatureTrustEngine(signatureTrustEngine);

        final SignatureSecurityHandler signatureHandler = new SignatureSecurityHandler();
        signatureHandler.setHttpServletRequestSupplier(NonnullSupplier.of(request));
        signatureHandler.initialize();

        Objects.requireNonNull(messageContext.getSubcontext(SAMLPeerEntityContext.class, true))
                .setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        Objects.requireNonNull(messageContext.getSubcontext(SAMLProtocolContext.class, true))
                .setProtocol(SAMLConstants.SAML20P_NS);
        Objects.requireNonNull(messageContext.getSubcontext(SecurityParametersContext.class, true))
                .setSignatureValidationParameters(sigValParams);

        signatureHandler.invoke(messageContext);

        final SAMLPeerEntityContext samlPeerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class);

        // Unfortunately the SignatureHandler lets messages with no signature or
        // malformed signatures pass.
        // Double-check that the handler has vouched for this message.
        assert samlPeerEntityContext != null;
        if (!samlPeerEntityContext.isAuthenticated()) {
            throw new MessageHandlerException("Message not authenticated");
        }

        final String entityId = samlPeerEntityContext.getEntityId();
        final CriteriaSet criteriaSet = new CriteriaSet();
        assert entityId != null;
        criteriaSet.add(new EntityIdCriterion(entityId));
        final Iterable<EntityDescriptor> descriptorIterable = metadataResolver.resolve(criteriaSet);
        if (StreamSupport.stream(descriptorIterable.spliterator(), false).findAny().isPresent()) {
            return descriptorIterable.iterator().next();
        }
        throw new MessageHandlerException("Message somehow not related to a metadata file");
    }
}
