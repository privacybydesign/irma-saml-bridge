package nl.sidn.irma.saml_bridge.service;

import nl.sidn.irma.saml_bridge.exception.BridgeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
class IrmaServiceTest {

    @Mock
    RestTemplate mockRestTemplate;

    @InjectMocks
    IrmaService irmaService;

    @Test
    void startSessionTest() throws BridgeException {
        String irmaResponse = "{}";
        ResponseEntity<String> response = new ResponseEntity<>(irmaResponse, HttpStatus.OK);
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(String.class))).thenReturn(response);
        String data = irmaService.startSession("accessToken", "http://dummy");
        verify(mockRestTemplate, times(1)).exchange(anyString(), any(), any(), eq(String.class));
        assertEquals(irmaResponse, data);
    }

    @Test
    void startSessionTestNoResponseBody() throws BridgeException {
        ResponseEntity<String> response = new ResponseEntity<>(HttpStatus.NO_CONTENT);
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(String.class))).thenReturn(response);
        irmaService.startSession("accessToken", "http://dummy");
        verify(mockRestTemplate, times(1)).exchange(anyString(), any(), any(), eq(String.class));
    }

    @Test
    void startSessionTestWithStatusCodeIsNot2xx() {
        ResponseEntity<String> response = new ResponseEntity<>(HttpStatus.TEMPORARY_REDIRECT);
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(String.class))).thenReturn(response);
        BridgeException exception = assertThrows(BridgeException.class, () -> irmaService.startSession("accessToken", "http://dummy"));
        assertEquals(500, exception.getHttpStatusCode());
    }


    @Test
    void startSessionTestWithException() {
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(String.class))).thenThrow(new HttpServerErrorException(HttpStatus.BAD_REQUEST, "error"));
        BridgeException exception = assertThrows(BridgeException.class, () -> irmaService.startSession("accessToken", "http://dummy"));
        assertEquals(500, exception.getHttpStatusCode());
    }

    @Test
    void startSessionTestWithHttpClientErrorException() {
        when(mockRestTemplate.exchange(anyString(), any(), any(), eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "error"));
        BridgeException exception = assertThrows(BridgeException.class, () -> irmaService.startSession("accessToken", "http://dummy"));
        assertEquals(400, exception.getHttpStatusCode());
    }
}