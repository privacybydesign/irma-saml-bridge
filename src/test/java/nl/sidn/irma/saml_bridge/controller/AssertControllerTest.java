package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.*;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.RedirectInstructionService;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import static nl.sidn.irma.saml_bridge.Fixtures.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AssertControllerTest {

    private static final String BASE_URL = "/assert";

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
        when(keyService.getIrmaPublicKey()).thenReturn(mock(RSAPublicKey.class));
        when(keyService.getJwtPublicKey()).thenReturn(mock(RSAPublicKey.class));
    }

    @Test
    void reportTest() throws Exception {
        AssertRequest assertRequestMock = assertRequest();
        RedirectInstruction redirectInstructionMock = redirectInstruction();

        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", objectMapperTest.writeValueAsString(new String[][][]{{{"12345"}}}));
        params.put("relay_state", "relay_state");

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", defaultDiscloseClaims("PRESENT"));
        claimsMap.put("proofStatus", "VALID");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);

        when(redirectInstructionService.create(any(AssertParameters.class), any(Disclosure.class), any(ResultStatus.class))).thenReturn(redirectInstructionMock);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(objectMapperTest.writeValueAsString(redirectInstructionMock), mvcResult.getResponse().getContentAsString());

    }

    @Test
    void reportTestMalformedException() throws Exception {
        AssertRequest assertRequestMock = assertRequest();
        RedirectInstruction redirectInstructionMock = redirectInstruction();

        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", objectMapperTest.writeValueAsString(new String[][][]{{{"12345"}}}));
        params.put("relay_state", "relay_state");

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", "malformedClaim");
        claimsMap.put("proofStatus", "VALID");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);

        when(redirectInstructionService.create(any(AssertParameters.class), any(Disclosure.class), any(ResultStatus.class))).thenReturn(redirectInstructionMock);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isBadRequest())
                .andReturn();

        assertEquals("Received malformed disclosure", mvcResult.getResponse().getContentAsString());

    }

    @Test
    void reportTestNotValidIrmaResponseNoAttributes() throws Exception {
        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", "condiscon");
        params.put("relay_state", "relay_state");

        AssertRequest assertRequestMock = assertRequest();
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", defaultDiscloseClaims("PRESENT1"));
        claimsMap.put("proofStatus", "VALID");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertEquals("Expected valid proof and present attributes", mvcResult.getResponse().getContentAsString());
    }

    @Test
    void reportTestNotValid() throws Exception {
        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", "condiscon");
        params.put("relay_state", "relay_state");

        AssertRequest assertRequestMock = assertRequest();
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", defaultDiscloseClaims("PRESENT"));
        claimsMap.put("proofStatus", "VALID1");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertEquals("Expected valid proof and present attributes", mvcResult.getResponse().getContentAsString());
    }

    @Test
    void reportTestNotMatchingCondiscons() throws Exception {
        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", objectMapperTest.writeValueAsString(new String[][][]{{{"1234566"}}}));
        params.put("relay_state", "relay_state");

        AssertRequest assertRequestMock = assertRequest();
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", defaultDiscloseClaims("PRESENT"));
        claimsMap.put("proofStatus", "VALID");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);

        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertEquals("The disclosure does not match the requested condiscon", mvcResult.getResponse().getContentAsString());
    }

    @Test
    void reportTestBridgeException() throws Exception {
        Map<String, Object> params = new TreeMap<>();
        params.put("sp_name", "sp_name");
        params.put("request_id", "request_id");
        params.put("service_url", "service_url");
        params.put("issuer", "issuer");
        params.put("condiscon", objectMapperTest.writeValueAsString(new String[][][]{{{"12345"}}}));
        params.put("relay_state", "relay_state");

        AssertRequest assertRequestMock = assertRequest();
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("disclosed", defaultDiscloseClaims("PRESENT"));
        claimsMap.put("proofStatus", "VALID");
        claimsMap.put("token", "token");
        claimsMap.put("aparams", params);

        Claims claims = Jwts.claims().add(claimsMap).build();
        Jws<Claims> claimsJws = mock(Jws.class);
        when(claimsJws.getPayload()).thenReturn(claims);
        when(jwtUtil.getClaims(any(PublicKey.class), anyString())).thenReturn(claimsJws);
        when(redirectInstructionService.create(any(AssertParameters.class), any(Disclosure.class), any(ResultStatus.class))).thenThrow(new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "error"));
        MvcResult mvcResult = mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapperTest.writeValueAsString(assertRequestMock))
                )
                .andExpect(status().isInternalServerError())
                .andReturn();

        assertEquals("error", mvcResult.getResponse().getContentAsString());
    }

}