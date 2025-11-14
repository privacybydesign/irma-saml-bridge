package nl.sidn.irma.saml_bridge.controller;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import nl.sidn.irma.saml_bridge.model.ClientError;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.SignatureValidationService;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.Reader;

import static org.assertj.core.api.Assertions.assertThat;
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

    @Test
    void report_returns200_when_messages_is_sanitized() throws Exception {
        final ClientError clientError = new ClientError();
        setField(clientError, "source", "ui.js");
        setField(clientError, "lineno", 12);
        setField(clientError, "colno", 34);
        setField(clientError, "message", "Unexpected token");

        when(objectMapper.readValue(any(Reader.class), eq(ClientError.class))).thenReturn(clientError);

        mockMvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content("{\"source\":\"ui.js\",\"lineno\":12,\"colno\":34,\"message\":\"Unexpected token\"}")).andExpect(status().isOk());

        verify(objectMapper, times(1)).readValue(any(Reader.class), eq(ClientError.class));
    }

    @Test
    void report_sanitizes_source_and_message_in_log_and_returns_200() throws Exception {
        // GIVEN a ClientError with control characters (CR, LF, TAB, NUL, DEL)
        final String rawSource = "app/ui.js\r\npath\t\u0000\u007F";
        final String rawMessage = "TypeError:\nfoo() is not a function\r\n\tat line 12\u0000";

        // Expected sanitization: all control chars replaced by a single space
        final String expectedSource = "app/ui.js path  ";
        final String expectedMessage = "TypeError: foo() is not a function  at line 12 ";

        final ClientError ce = new ClientError();
        setField(ce, "source", rawSource);
        setField(ce, "lineno", 12);
        setField(ce, "colno", 34);
        setField(ce, "message", rawMessage);

        when(objectMapper.readValue(any(Reader.class), eq(ClientError.class))).thenReturn(ce);

        // Capture WARN logs from the controller
        final ListAppender<ILoggingEvent> appender = attachListAppender();

        // WHEN calling the endpoint
        mockMvc.perform(post("/report")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ignored\":\"because we mock ObjectMapper\"}"))
                .andExpect(status().isOk());

        // THEN the WARN log line contains sanitized source and message
        final ILoggingEvent warnEvent = appender.list.stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .reduce((first, second) -> second) // last WARN entry
                .orElse(null);

        assertThat(warnEvent).as("A WARN log entry should be emitted").isNotNull();

        final String formatted = warnEvent.getFormattedMessage();

        assertThat(formatted)
                .contains("action=\"clientsideerror\"")
                .contains("linenr=\"12\"")
                .contains("colnr=\"34\"")
                // one space between "js" and "path", and allow trailing whitespace before the closing quote
                .containsPattern("source=\"app/ui.js path")
                // spaces where control chars were, allow trailing whitespace before the closing quote
                .containsPattern("message=\"TypeError: foo\\(\\) is not a function at line 12");
    }

    private ListAppender<ILoggingEvent> attachListAppender() {
        final Logger logger = (Logger) LoggerFactory.getLogger(ErrorReportController.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        return appender;
    }

    // --- small helper for setting fields if ClientError is a simple POJO with private fields ---
    private static void setField(final Object target, final String fieldName, final Object value) throws Exception {
        final var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }
}
