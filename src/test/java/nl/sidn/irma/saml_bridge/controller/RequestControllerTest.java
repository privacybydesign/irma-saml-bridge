package nl.sidn.irma.saml_bridge.controller;

import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.SignatureValidationService;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import net.shibboleth.shared.xml.SerializeSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.w3c.dom.Element;

import jakarta.servlet.http.HttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RequestControllerTest {

    private static final String BASE_URL = "/request";
    private static final String SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    @Autowired
    MockMvc mockMvc;

    // Mocked so the request bypasses real signature verification and resolves to a
    // controlled SP descriptor; the real OpenSamlService still performs the ACS check.
    @MockitoBean
    private SignatureValidationService signatureValidationService;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() throws Exception {
        InitializationService.initialize();
    }

    @Test
    void requestWithUnregisteredAcsUrlIsRejected() throws Exception {
        // A signed AuthnRequest whose AssertionConsumerServiceURL is NOT registered in
        // the SP metadata must be rejected (SAML 2.0 core §3.4.1.1), otherwise the signed
        // assertion could be redirected to an attacker-chosen location.
        String samlRequest = encodeAuthnRequest("https://attacker.example.com/steal");

        EntityDescriptor entityDescriptor = mock(EntityDescriptor.class);
        SPSSODescriptor spssoDescriptor = mock(SPSSODescriptor.class);
        AssertionConsumerService registeredAcs = mock(AssertionConsumerService.class);
        when(registeredAcs.getLocation()).thenReturn("https://sp.example/acs");
        when(spssoDescriptor.getAssertionConsumerServices()).thenReturn(List.of(registeredAcs));
        when(entityDescriptor.getSPSSODescriptor(SAML_PROTOCOL_NS)).thenReturn(spssoDescriptor);
        when(signatureValidationService.verifySignature(any(HttpServletRequest.class), any(MessageContext.class)))
                .thenReturn(entityDescriptor);

        mockMvc.perform(get(BASE_URL).param("SAMLRequest", samlRequest))
                .andExpect(status().isBadRequest())
                .andExpect(request().attribute("error",
                        "Requested AssertionConsumerServiceURL is not registered in SP metadata"));
    }

    /**
     * Build a minimal AuthnRequest with the given ACS URL and encode it for the SAML 2.0
     * HTTP-Redirect binding (raw DEFLATE + Base64), matching what the decoder expects.
     */
    private String encodeAuthnRequest(String acsUrl) throws Exception {
        AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setID("_test-request-id");
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setAssertionConsumerServiceURL(acsUrl);

        Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://sp.example/metadata");
        authnRequest.setIssuer(issuer);

        Element element = XMLObjectSupport.marshall(authnRequest);
        String xml = SerializeSupport.nodeToString(element);

        ByteArrayOutputStream deflated = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflaterStream = new DeflaterOutputStream(deflated,
                new Deflater(Deflater.DEFLATED, true))) {
            deflaterStream.write(xml.getBytes(StandardCharsets.UTF_8));
        }

        return Base64.getEncoder().encodeToString(deflated.toByteArray());
    }
}
