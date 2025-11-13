package nl.sidn.irma.saml_bridge.service;

import com.google.common.io.BaseEncoding;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.model.Disclosure;
import nl.sidn.irma.saml_bridge.model.ResultStatus;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.saml.saml2.metadata.impl.*;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoImpl;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.impl.X509CertificateImpl;
import org.opensaml.xmlsec.signature.impl.X509DataImpl;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

/**
 * Service that initializes the OpenSAML library and provides the base
 * functionality
 * as used by this daemon.
 */
@Service("OpenSamlService")
public class OpenSamlService {

    private static final String SAML_BINDINGS_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

    private final ConfigurationService configurationService;

    private final KeyService keyService;

    private final ParserPool parserPool;

    public OpenSamlService(
            final ConfigurationService configurationService,
            final KeyService keyService,
            final ParserPool parserPool) throws InitializationException {
        this.configurationService = configurationService;
        this.keyService = keyService;
        this.parserPool = parserPool;

        initialize();
    }

    /**
     * Attempt to initialize OpenSAML.
     * It is unclear when this should fail.
     * Perhaps when the POM is misconfigured and we failed to properly build.
     *
     * @throws InitializationException The initialization exception is thrown when OpenSAML fails to initialize.
     */
    private void initialize() throws InitializationException {
        InitializationService.initialize();
    }

    /**
     * Construct a KeyInfo XML object for our SAML certificate.
     *
     * @return The KeyInfo XML object.
     * @throws CertificateEncodingException The certificate encoding exception is thrown when the SAML certificate cannot be encoded.
     */
    private KeyInfo createKeyInfoForCertificate() throws CertificateEncodingException {
        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final XMLObjectBuilder<KeyInfoImpl> keyInfoBuilder = (XMLObjectBuilder<KeyInfoImpl>) factory
                .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final XMLObjectBuilder<X509DataImpl> x509Builder = (XMLObjectBuilder<X509DataImpl>) factory
                .getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final XMLObjectBuilder<X509CertificateImpl> certBuilder = (XMLObjectBuilder<X509CertificateImpl>) factory
                .getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);

        final String value = new String(Base64.getEncoder().encode(this.keyService.getSamlCertificate().getEncoded()));
        assert certBuilder != null;
        final X509Certificate cert = certBuilder.buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
        cert.setValue(value);

        final X509DataImpl x509 = x509Builder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
        x509.getX509Certificates().add(cert);

        final KeyInfo keyInfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        keyInfo.getX509Datas().add(x509);

        return keyInfo;
    }

    /**
     * Construct a generic signature preloaded with our SAML private key and
     * certificate.
     * Will use SHA256 to construct the signature.
     *
     * @return The Signature XML object.
     * @throws CertificateEncodingException The certificate encoding exception is thrown when the SAML certificate cannot be encoded.
     */
    private Signature createSignature() throws CertificateEncodingException {
        final Credential credential = new BasicX509Credential(
                this.keyService.getSamlCertificate(),
                this.keyService.getSamlPrivateKey());

        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final XMLObjectBuilder<SignatureImpl> builder = (XMLObjectBuilder<SignatureImpl>) factory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        final Signature signature = builder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setKeyInfo(this.createKeyInfoForCertificate());

        return signature;
    }

    /**
     * Construct a typical Issuer XML object for our Identity Provider string.
     */
    private Issuer createIssuer() {
        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<IssuerImpl> issuerBuilder = (SAMLObjectBuilder<IssuerImpl>) factory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        final IssuerImpl issuer = issuerBuilder.buildObject();
        issuer.setValue(this.configurationService.getConfiguration().getIssuerName());

        return issuer;
    }

    /**
     * Create a SAML assertion response XML object.
     *
     * @param assertParameters The assertion parameters including the intended
     *                         recipient for our assertion.
     * @param disclosure       The disclosure as done by IRMA to supply the user
     *                         credentials for this assertion. May be NULL when
     *                         status is not SUCCESS.
     * @param resultStatus     The status of the result.
     * @return The SAML assertion response XML object.
     */
    public Response createAssertionResponse(final AssertParameters assertParameters, final Disclosure disclosure,
                                            final ResultStatus resultStatus) {
        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AuthnStatementImpl> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatementImpl>) factory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AttributeStatementImpl> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatementImpl>) factory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AttributeImpl> attributeBuilder = (SAMLObjectBuilder<AttributeImpl>) factory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final XMLObjectBuilder<XSString> xsStringBuilder = (XMLObjectBuilder<XSString>) factory
                .getBuilder(XSString.TYPE_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AuthnContextImpl> authnContextBuilder = (SAMLObjectBuilder<AuthnContextImpl>) factory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AuthnContextClassRefImpl> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRefImpl>) factory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<SubjectImpl> subjectBuilder = (SAMLObjectBuilder<SubjectImpl>) factory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<SubjectConfirmationImpl> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmationImpl>) factory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<SubjectConfirmationDataImpl> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationDataImpl>) factory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AssertionImpl> assertionBuilder = (SAMLObjectBuilder<AssertionImpl>) factory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<StatusImpl> statusBuilder = (SAMLObjectBuilder<StatusImpl>) factory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<StatusCodeImpl> statusCodeBuilder = (SAMLObjectBuilder<StatusCodeImpl>) factory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<StatusMessageImpl> statusMessageBuilder = (SAMLObjectBuilder<StatusMessageImpl>) factory
                .getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<ResponseImpl> responseBuilder = (SAMLObjectBuilder<ResponseImpl>) factory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<ConditionsImpl> conditionsBuilder = (SAMLObjectBuilder<ConditionsImpl>) factory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AudienceRestrictionImpl> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestrictionImpl>) factory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AudienceImpl> audienceBuilder = (SAMLObjectBuilder<AudienceImpl>) factory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<NameIDImpl> nameIDBuilder = (SAMLObjectBuilder<NameIDImpl>) factory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);

        final Instant now = LocalDateTime.now().toInstant(ZoneOffset.UTC);
        final Instant until = now.plusSeconds(configurationService.getConfiguration().getResponseTtlInSec());

        final AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setURI("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        final AuthnContextImpl authnContext = authnContextBuilder.buildObject();
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        final AudienceImpl audience = audienceBuilder.buildObject();
        final AudienceRestrictionImpl audienceRestriction = audienceRestrictionBuilder.buildObject();

        audience.setURI(assertParameters.getIssuer());
        audienceRestriction.getAudiences().add(audience);

        final ConditionsImpl conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(until);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        final AuthnStatementImpl authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(now);
        authnStatement.setAuthnContext(authnContext);

        final SubjectImpl subject = subjectBuilder.buildObject();
        final StatusCodeImpl statusCode = statusCodeBuilder.buildObject();

        String id = null;

        final StatusImpl status = statusBuilder.buildObject();

        final ResponseImpl response = responseBuilder.buildObject();

        if (resultStatus == ResultStatus.SUCCESS) {
            // Set nameID to first attribute, assuming we have such and attribute.
            final Optional<Map.Entry<String, String>> firstAttribute = disclosure.getAttributes()
                    .entrySet()
                    .stream()
                    .findFirst();
            if (firstAttribute.isPresent()) {
                final NameID nameID = nameIDBuilder.buildObject();
                nameID.setFormat(NameID.TRANSIENT);
                nameID.setValue(firstAttribute.get().getValue());
                subject.setNameID(nameID);
            }

            final AttributeStatementImpl attributeStatement = attributeStatementBuilder.buildObject();
            for (final Map.Entry<String, String> entry : disclosure.getAttributes().entrySet()) {
                final XSString attributeValue = xsStringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSString.TYPE_NAME);
                attributeValue.setValue(entry.getValue());

                final AttributeImpl attribute = attributeBuilder.buildObject();
                attribute.setName(entry.getKey());
                attribute.getAttributeValues().add(attributeValue);

                attributeStatement.getAttributes().add(attribute);
            }

            final AssertionImpl assertion = assertionBuilder.buildObject();
            assertion.getAttributeStatements().add(attributeStatement);

            // Our assertion ID refers to the IRMA session.
            if (disclosure.getToken() != null) {
                id = disclosure.getToken();
            } else {
                id = generateId();
            }
            assertion.setID("_" + BaseEncoding.base16().encode(id.getBytes()));

            assertion.setSubject(subject);
            assertion.setIssuer(this.createIssuer());
            assertion.setIssueInstant(now);
            assertion.getAuthnStatements().add(authnStatement);
            assertion.setConditions(conditions);

            response.getAssertions().add(assertion);

            statusCode.setValue(StatusCode.SUCCESS);
        } else if (resultStatus == ResultStatus.FAILED) {
            final StatusCodeImpl statusCodeError = statusCodeBuilder.buildObject();

            statusCodeError.setValue(StatusCode.AUTHN_FAILED);

            statusCode.setValue(StatusCode.RESPONDER);
            statusCode.setStatusCode(statusCodeError);

            // Add errormessage, see IRMA-1184
            final StatusMessageImpl statusMessage = statusMessageBuilder.buildObject();
            statusMessage.setValue((assertParameters.getRequestError().getMessage() != null)
                    ? assertParameters.getRequestError().getMessage()
                    : "");
            status.setStatusMessage(statusMessage);

            id = generateId();
        }

        final SubjectConfirmationDataImpl subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
        subjectConfirmationData.setRecipient(assertParameters.getServiceUrl());
        subjectConfirmationData.setInResponseTo(assertParameters.getRequestId());
        subjectConfirmationData.setNotOnOrAfter(until);

        final SubjectConfirmationImpl sc = subjectConfirmationBuilder.buildObject();
        // The bearer of this assertion is authenticated for the contained attributes.
        sc.setMethod(SubjectConfirmation.METHOD_BEARER);
        sc.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(sc);

        status.setStatusCode(statusCode);

        response.setID(id);
        response.setIssuer(this.createIssuer());
        response.setIssueInstant(now);
        response.setInResponseTo(assertParameters.getRequestId());
        response.setDestination(assertParameters.getServiceUrl());
        response.setStatus(status);

        return response;
    }

    /**
     * Generate a random identifier
     *
     * @return A String containing the randomly generated identifier
     */
    private String generateId() {
        final byte[] bytes = new byte[20];
        final Random random = new Random();
        random.nextBytes(bytes);
        return new String(Base64.getEncoder().encode(bytes));
    }

    /**
     * Marshall a SAML assertion response and sign it.
     *
     * @param response The response to be marshalled and signed.
     * @return A XML text string containing the signed SAML assertion.
     * @throws MarshallingException         The marshalling exception is thrown when the SAML response cannot be marshalled.
     * @throws TransformerException         The transformer exception is thrown when the SAML response cannot be transformed to a string.
     * @throws SignatureException           The signature exception is thrown when the SAML response cannot be signed.
     * @throws CertificateEncodingException The certificate encoding exception is thrown when the SAML certificate cannot be encoded.
     */
    public String marshallResponse(final Response response)
            throws MarshallingException, TransformerException, SignatureException, CertificateEncodingException {
        final MarshallerFactory factory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        final ResponseMarshaller marshaller = (ResponseMarshaller) factory.getMarshaller(response);

        final Signature signature = this.createSignature();
        response.setSignature(signature);

        final Element element = marshaller.marshall(response);
        Signer.signObject(signature);

        return this.marshallToString(element);
    }

    /**
     * Create a SAML metadata XML object for our Identity Provider.
     *
     * @return The SAML metadata XML object.
     * @throws CertificateEncodingException The certificate encoding exception is thrown when the SAML certificate cannot be encoded.
     */
    public EntityDescriptor createIdPMetadata() throws CertificateEncodingException {
        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<EntityDescriptorImpl> edBuilder = (SAMLObjectBuilder<EntityDescriptorImpl>) factory
                .getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<IDPSSODescriptorImpl> idpssodBuilder = (SAMLObjectBuilder<IDPSSODescriptorImpl>) factory
                .getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<KeyDescriptorImpl> keydBuilder = (SAMLObjectBuilder<KeyDescriptorImpl>) factory
                .getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<SingleSignOnServiceImpl> ssosBuilder = (SAMLObjectBuilder<SingleSignOnServiceImpl>) factory
                .getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);

        final Configuration configuration = this.configurationService.getConfiguration();

        final IDPSSODescriptorImpl idpSsoDescriptor = idpssodBuilder.buildObject();
        idpSsoDescriptor.setWantAuthnRequestsSigned(true);

        // We only include a signing key.
        final KeyInfo keyInfo = this.createKeyInfoForCertificate();

        final KeyDescriptorImpl sigKey = keydBuilder.buildObject();
        sigKey.setUse(UsageType.SIGNING);
        sigKey.setKeyInfo(keyInfo);

        idpSsoDescriptor.getKeyDescriptors().add(sigKey);
        idpSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        final SingleSignOnServiceImpl singleSignOnService = ssosBuilder.buildObject();
        // We only support HTTP redirects.
        singleSignOnService.setBinding(SAML_BINDINGS_REDIRECT);
        singleSignOnService.setLocation(configuration.constructUrl("/request"));

        idpSsoDescriptor.getSingleSignOnServices().add(singleSignOnService);

        final EntityDescriptorImpl entityDescriptor = edBuilder.buildObject();
        entityDescriptor.setEntityID(configuration.getIssuerName());
        entityDescriptor.getRoleDescriptors().add(idpSsoDescriptor);
        entityDescriptor.setCacheDuration(Duration.of(30000L, ChronoUnit.MILLIS));

        return entityDescriptor;
    }

    /**
     * Create a SAML metadata XML object for our Service Provider.
     * Meant exclusively for testing.
     *
     * @return The SAML metadata XML object.
     * @throws CertificateEncodingException The certificate encoding exception is thrown when the SAML certificate cannot be encoded.
     */
    public EntityDescriptor createSPMetadata() throws CertificateEncodingException {
        final Configuration configuration = this.configurationService.getConfiguration();

        final XMLObjectBuilderFactory factory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        @SuppressWarnings("unchecked") final SAMLObjectBuilder<EntityDescriptorImpl> edBuilder = (SAMLObjectBuilder<EntityDescriptorImpl>) factory
                .getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<SPSSODescriptorImpl> spssodBuilder = (SAMLObjectBuilder<SPSSODescriptorImpl>) factory
                .getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<KeyDescriptorImpl> keydBuilder = (SAMLObjectBuilder<KeyDescriptorImpl>) factory
                .getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<AssertionConsumerServiceImpl> assertionConsumerServiceBuilder = (SAMLObjectBuilder<AssertionConsumerServiceImpl>) factory
                .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<OrganizationURLImpl> urlBuilder = (SAMLObjectBuilder<OrganizationURLImpl>) factory
                .getBuilder(OrganizationURL.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<OrganizationNameImpl> nameBuilder = (SAMLObjectBuilder<OrganizationNameImpl>) factory
                .getBuilder(OrganizationName.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<OrganizationDisplayNameImpl> displayNameBuilder = (SAMLObjectBuilder<OrganizationDisplayNameImpl>) factory
                .getBuilder(OrganizationDisplayName.DEFAULT_ELEMENT_NAME);
        @SuppressWarnings("unchecked") final SAMLObjectBuilder<OrganizationImpl> organizationBuilder = (SAMLObjectBuilder<OrganizationImpl>) factory
                .getBuilder(Organization.DEFAULT_ELEMENT_NAME);

        final SPSSODescriptorImpl spSsoDescriptor = spssodBuilder.buildObject();
        spSsoDescriptor.setWantAssertionsSigned(true);

        // We only include a signing key.
        final KeyInfo keyInfo = this.createKeyInfoForCertificate();

        final KeyDescriptorImpl sigKey = keydBuilder.buildObject();
        sigKey.setUse(UsageType.SIGNING);
        sigKey.setKeyInfo(keyInfo);

        spSsoDescriptor.getKeyDescriptors().add(sigKey);
        spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        final AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        assertionConsumerService.setIndex(0);
        assertionConsumerService.setBinding(SAML_BINDINGS_REDIRECT);
        assertionConsumerService.setLocation("/irma-saml-bridge/test/return");
        spSsoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        final OrganizationDisplayNameImpl organizationDisplayName = displayNameBuilder.buildObject();
        organizationDisplayName.setValue("SIDN");
        organizationDisplayName.setXMLLang("en");

        final OrganizationNameImpl organizationName = nameBuilder.buildObject();
        organizationName.setValue("SIDN");
        organizationName.setXMLLang("en");

        final OrganizationURLImpl organizationUrl = urlBuilder.buildObject();
        organizationUrl.setURI(configuration.constructUrl("/test/metadata"));
        organizationUrl.setXMLLang("en");

        final OrganizationImpl organization = organizationBuilder.buildObject();
        organization.getURLs().add(organizationUrl);
        organization.getDisplayNames().add(organizationDisplayName);
        organization.getOrganizationNames().add(organizationName);

        spSsoDescriptor.setOrganization(organization);

        final EntityDescriptorImpl entityDescriptor = edBuilder.buildObject();
        entityDescriptor.setEntityID(configuration.getIssuerName());
        entityDescriptor.getRoleDescriptors().add(spSsoDescriptor);
        entityDescriptor.setCacheDuration(Duration.of(30000L, ChronoUnit.MILLIS));

        return entityDescriptor;
    }

    /**
     * Marshall a SAML metadata object.
     * This object is not signed.
     *
     * @param metadata The metadata to be marshalled.
     * @return A XML string containing the SAML metadata object.
     * @throws MarshallingException The marshalling exception is thrown when the SAML metadata cannot be marshalled.
     * @throws TransformerException The transformer exception is thrown when the SAML metadata cannot be transformed to a string.
     */
    public String marshallMetadata(final EntityDescriptor metadata) throws MarshallingException, TransformerException {
        final MarshallerFactory factory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        final EntityDescriptorMarshaller marshaller = (EntityDescriptorMarshaller) factory.getMarshaller(metadata);

        return this.marshallToString(marshaller.marshall(metadata));
    }

    /**
     * Marshall a XML object to a string.
     *
     * @param element The XML element to be marshalled.
     * @return A string containing the XML object.
     * @throws TransformerException The transformer exception is thrown when the XML object cannot be transformed to a string.
     */
    private String marshallToString(final Element element) throws TransformerException {
        final DOMSource domSource = new DOMSource(element);
        final StringWriter writer = new StringWriter();
        final StreamResult result = new StreamResult(writer);

        // Prevent XXE attacks when parsing element.
        final TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        final Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);

        return writer.toString();
    }

    /**
     * Given a string with a SAML assertion, verify that it is properly formed and
     * is correctly signed.
     *
     * @param response The SAML assertion response as a string.
     * @throws SignatureException     Thrown when the signature is incorrect.
     * @throws UnmarshallingException The unmarshalling exception is thrown when the SAML response cannot be unmarshalled.
     * @throws XMLParserException     The XML parser exception is thrown when the SAML response cannot be parsed.
     */
    public void verifyAssertionResponse(final String response)
            throws SignatureException, XMLParserException, UnmarshallingException {
        final Response result = (Response) XMLObjectSupport.unmarshallFromReader(
                parserPool, new StringReader(response));

        final Credential credential = new BasicX509Credential(
                this.keyService.getSamlCertificate());

        final SAMLSignatureProfileValidator pv = new SAMLSignatureProfileValidator();
        pv.validate(result.getSignature());
        SignatureValidator.validate(result.getSignature(), credential);
    }

    /**
     * Find the appropriate location to return to from a metadata EntityDescriptor.
     * <p>
     * As we only support the HTTP Redirect SAML2 binding, we search for that one
     * only, and reject all others.
     *
     * @param entityDescriptor The descriptor for the applicable metadata, which can
     *                         be retrieved from the SignatureValidationService.
     */
    public String findRedirectAssertionConsumerService(final EntityDescriptor entityDescriptor) {
        final SPSSODescriptor spssoDescriptor = entityDescriptor.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");

        if (spssoDescriptor == null) {
            return null;
        }

        for (final AssertionConsumerService assertionConsumerService : spssoDescriptor.getAssertionConsumerServices()) {
            if (assertionConsumerService.getBinding().equals(SAML_BINDINGS_REDIRECT)) {
                return assertionConsumerService.getLocation();
            }
        }

        return null;
    }
}
