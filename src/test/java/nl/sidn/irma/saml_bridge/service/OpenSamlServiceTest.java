package nl.sidn.irma.saml_bridge.service;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.Disclosure;
import nl.sidn.irma.saml_bridge.model.ResultStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static nl.sidn.irma.saml_bridge.Fixtures.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
class OpenSamlServiceTest {

    @Mock
    private ConfigurationService configurationService;

    @Mock
    private KeyService keyService;

    @Mock
    private ParserPool parserPool;

    @InjectMocks
    OpenSamlService openSamlService;

    @BeforeEach
    void setUp() throws CertificateEncodingException {
        when(configurationService.getConfiguration()).thenReturn(configuration());
        when(keyService.getSamlCertificate()).thenReturn(mock(X509Certificate.class));
        when(keyService.getSamlCertificate().getEncoded()).thenReturn("test".getBytes());
    }

    @Test
    void createAssertionResponseTestResultStatusIsSUCCESS() {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosureMock = disclosure();
        Response response = openSamlService.createAssertionResponse(assertParameters, disclosureMock, ResultStatus.SUCCESS);
        assertNotNull(response);
    }

    @Test
    void createAssertionResponseTestResultStatusIsFAILED() {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosureMock = disclosure();
        Response response = openSamlService.createAssertionResponse(assertParameters, disclosureMock, ResultStatus.FAILED);
        assertNotNull(response);
    }

    @Test
    void createAssertionResponseTestNoDisclosureAttributes() {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosureMock = disclosure(disclosure -> {
            disclosure.setAttributes(Collections.emptyMap());
        });
        Response response = openSamlService.createAssertionResponse(assertParameters, disclosureMock, ResultStatus.SUCCESS);
        assertNotNull(response);
    }

    @Test
    void createAssertionResponseTestWhenDisclosureTokenIsNull() {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosureMock = disclosure(disclosure -> {
            disclosure.setToken(null);
        });
        Response response = openSamlService.createAssertionResponse(assertParameters, disclosureMock, ResultStatus.SUCCESS);
        assertNotNull(response);
    }

    @Test
    void createIdPMetadataTest() throws CertificateEncodingException {
        EntityDescriptor entityDescriptor = openSamlService.createIdPMetadata();
        assertNotNull(entityDescriptor);
    }

    @Test
    void createSPMetadataTest() throws CertificateEncodingException {
        EntityDescriptor entityDescriptor = openSamlService.createSPMetadata();
        assertNotNull(entityDescriptor);
    }

}