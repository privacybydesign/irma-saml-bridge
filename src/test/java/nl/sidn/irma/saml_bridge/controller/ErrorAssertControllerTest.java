package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.AssertRequest;
import nl.sidn.irma.saml_bridge.model.RedirectInstruction;
import nl.sidn.irma.saml_bridge.model.ResultStatus;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.RedirectInstructionService;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.TreeMap;

import static nl.sidn.irma.saml_bridge.Fixtures.assertRequest;
import static nl.sidn.irma.saml_bridge.Fixtures.redirectInstruction;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ErrorAssertControllerTest {

    private static final String BASE_URL = "/errorassert";

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    JwtUtil jwtUtil;

    @MockitoBean
    private RedirectInstructionService redirectInstructionService;

    @Autowired
    ObjectMapper objectMapperTest;

    @BeforeEach
    void init() {
        when(keyService.getJwtPrivateKey()).thenReturn(mock(RSAPrivateKey.class));
        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", "condiscon");
        params.put("relay_state", "relay_state");

        Claims claims = Jwts.claims().build();
        claims.put("aparams", params);

        @SuppressWarnings("unchecked") Jws<Claims> claimsJws = (Jws<Claims>) mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);
    }

    @Test
    void errorTest() throws Exception {
        AssertRequest assertRequestMock = assertRequest();
        RedirectInstruction redirectInstructionMock = redirectInstruction();

        when(redirectInstructionService.create(any(AssertParameters.class), any(ResultStatus.class))).thenReturn(redirectInstructionMock);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(objectMapperTest.writeValueAsString(redirectInstructionMock), mvcResult.getResponse().getContentAsString());

    }

    @Test
    void errorAbortTest() throws Exception {
        AssertRequest assertRequestMock = assertRequest();
        RedirectInstruction redirectInstructionMock = redirectInstruction();

        when(redirectInstructionService.create(any(AssertParameters.class), any(ResultStatus.class))).thenReturn(redirectInstructionMock);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL + "/abort")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(objectMapperTest.writeValueAsString(redirectInstructionMock), mvcResult.getResponse().getContentAsString());

    }

    @Test
    void errorTestWithBridgeException() throws Exception {
        AssertRequest assertRequestMock = assertRequest();

        when(redirectInstructionService.create(any(AssertParameters.class), any(ResultStatus.class))).thenThrow(new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "error"));
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isInternalServerError())
                .andReturn();

        assertEquals("error", mvcResult.getResponse().getContentAsString());

    }
}