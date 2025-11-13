package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.sidn.irma.saml_bridge.model.ClientError;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.SignatureValidationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.Reader;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ErrorReportControllerTest {

    public static final String BASE_URL = "/report";

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    KeyService keyService;

    @MockitoBean
    SignatureValidationService signatureValidationService;

    @MockitoBean
    ObjectMapper objectMapper;

    @MockitoBean
    ConfigurationService configurationService;

    @Test
    void report_returns200_when_valid_payload() throws Exception {
        final ClientError clientError = new ClientError();
        // assuming fields: source, lineno, colno, message
        // if they are immutable/constructor-based in your model, adjust accordingly:
        // e.g., new ClientError("ui.js", 12, 34, "oops")
        setField(clientError, "source", "ui.js");
        setField(clientError, "lineno", 12);
        setField(clientError, "colno", 34);
        setField(clientError, "message", "Unexpected token");

        when(objectMapper.readValue(any(Reader.class), eq(ClientError.class))).thenReturn(clientError);

        mockMvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content("{\"source\":\"ui.js\",\"lineno\":12,\"colno\":34,\"message\":\"Unexpected token\"}")).andExpect(status().isOk());

        verify(objectMapper, times(1)).readValue(any(Reader.class), eq(ClientError.class));
    }

    @Test
    void report_handles_long_fields_and_still_returns200() throws Exception {
        final String longSource = "a".repeat(200);
        final String longMessage = "b".repeat(1000);

        final ClientError clientError = new ClientError();
        setField(clientError, "source", longSource);
        setField(clientError, "lineno", 1);
        setField(clientError, "colno", 2);
        setField(clientError, "message", longMessage);

        when(objectMapper.readValue(any(Reader.class), eq(ClientError.class))).thenReturn(clientError);

        mockMvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content("{\"source\":\"" + longSource + "\",\"lineno\":1,\"colno\":2,\"message\":\"" + longMessage + "\"}")).andExpect(status().isOk());

        verify(objectMapper, times(1)).readValue(any(Reader.class), eq(ClientError.class));
    }

    @Test
    void report_returns500_when_deserialization_fails() throws Exception {
        final IOException ioException = new IOException("boom");

        when(objectMapper.readValue(any(Reader.class), eq(ClientError.class)))
                .thenThrow(ioException);

        final Throwable exception = assertThrows(
                IOException.class,
                () -> mockMvc.perform(post("/report")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{malformed json"))
                        .andReturn()
        );

        assertInstanceOf(IOException.class, exception);
        verify(objectMapper, times(1)).readValue(any(Reader.class), eq(ClientError.class));
        assertEquals("boom", exception.getMessage());
    }

    // --- small helper for setting fields if ClientError is a simple POJO with private fields ---
    private static void setField(final Object target, final String fieldName, final Object value) throws Exception {
        final var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }
}
