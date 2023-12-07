package nl.sidn.irma.saml_bridge.controller;

import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.OpenSamlService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MetadataControllerTest {

    private static final String BASE_URL = "/metadata";

    @Autowired
    MockMvc mockMvc;

    @Autowired
    private OpenSamlService openSamlService;

    @MockBean
    KeyService keyService;

    @Test
    void metadataTest() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get(BASE_URL))
                .andExpect(status().isOk())
                .andReturn();

        assertNotEquals("error", mvcResult.getResponse().getContentAsString());
    }

    @Test
    void metadataTestThrowCertificateEncodingException() throws Exception {
        when(keyService.getSamlCertificate()).thenReturn(mock(X509Certificate.class));
        when(keyService.getSamlCertificate().getEncoded()).thenThrow(mock(CertificateEncodingException.class));
        MvcResult mvcResult = mockMvc.perform(get(BASE_URL))
                .andExpect(status().isInternalServerError())
                .andReturn();

        assertNotEquals("error", mvcResult.getResponse().getContentAsString());
    }
}