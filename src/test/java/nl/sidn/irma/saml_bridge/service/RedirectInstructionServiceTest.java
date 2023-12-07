package nl.sidn.irma.saml_bridge.service;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.Disclosure;
import nl.sidn.irma.saml_bridge.model.RedirectInstruction;
import nl.sidn.irma.saml_bridge.model.ResultStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.xml.transform.TransformerException;
import java.security.cert.CertificateEncodingException;

import static nl.sidn.irma.saml_bridge.Fixtures.assertParameters;
import static nl.sidn.irma.saml_bridge.Fixtures.disclosure;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
class RedirectInstructionServiceTest {

    @Mock
    private OpenSamlService openSamlService;

    @InjectMocks
    private RedirectInstructionService redirectInstructionService;

    @BeforeEach
    void setUp() {
    }

    @Test
    void createTest() throws BridgeException, MarshallingException, SecurityException, CertificateEncodingException, SignatureException, TransformerException, XMLParserException, UnmarshallingException {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosure = disclosure();

        when(openSamlService.createAssertionResponse(any(AssertParameters.class), any(Disclosure.class), any(ResultStatus.class))).thenReturn(mock(Response.class));
        when(openSamlService.marshallResponse(any(Response.class))).thenReturn("saml response");
        doNothing().when(openSamlService).verifyAssertionResponse(anyString());
        RedirectInstruction redirectInstruction = redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS);
        assertNotNull(redirectInstruction);
    }

    @Test
    void createTestExceptions() throws BridgeException, MarshallingException, SecurityException, CertificateEncodingException, SignatureException, TransformerException, XMLParserException, UnmarshallingException {
        AssertParameters assertParameters = assertParameters();
        Disclosure disclosure = disclosure();

        when(openSamlService.createAssertionResponse(any(AssertParameters.class), any(Disclosure.class), any(ResultStatus.class))).thenReturn(mock(Response.class));

        //MarshallingException
        when(openSamlService.marshallResponse(any(Response.class))).thenThrow(mock(MarshallingException.class));
        //doNothing().when(openSamlService).verifyAssertionResponse(anyString());
        BridgeException bridgeException = assertThrows(BridgeException.class, () -> redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS));
        assertEquals("Failed to marshall assertion", bridgeException.getMessage());

        //TransformerException
        when(openSamlService.marshallResponse(any(Response.class))).thenThrow(mock(TransformerException.class));
        bridgeException = assertThrows(BridgeException.class, () -> redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS));
        assertEquals("Failed to write assertion", bridgeException.getMessage());

        //SignatureException
        when(openSamlService.marshallResponse(any(Response.class))).thenThrow(mock(SignatureException.class));
        bridgeException = assertThrows(BridgeException.class, () -> redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS));
        assertEquals("Failed to write signature", bridgeException.getMessage());

        //UnmarshallingException
        when(openSamlService.marshallResponse(any(Response.class))).thenReturn("saml response");
        doThrow(mock(UnmarshallingException.class)).when(openSamlService).verifyAssertionResponse(anyString());
        bridgeException = assertThrows(BridgeException.class, () -> redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS));
        assertEquals("Failed to validate signature or format of our assertion", bridgeException.getMessage());
    }
}