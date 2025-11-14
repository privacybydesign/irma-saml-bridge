package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.model.ClientError;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/report")
public class ErrorReportController {

    private final ObjectMapper objectMapper;

    public ErrorReportController(final ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostMapping(value = "")
    public void report(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final ClientError error = objectMapper.readValue(request.getReader(), ClientError.class);

        log.warn(
                "action=\"clientsideerror\", source=\"{}\", linenr=\"{}\", colnr=\"{}\", message=\"{}\"",
                sanitizeForLog(limitString(error.getSource(), 50)),
                error.getLineno(),
                error.getColno(),
                sanitizeForLog(limitString(error.getMessage(), 256))
        );

        response.setStatus(200);
    }

    private static String limitString(final String str, final int length) {
        if (str == null) {
            return null;
        }

        if (str.length() > length) {
            return str.substring(0, length);
        }
        return str;
    }

    /**
     * Sanitize a string for safe logging by removing CR, LF and other control chars except printable ASCII.
     */
    private static String sanitizeForLog(final String input) {
        if (input == null) {
            return null;
        }
        // Remove CR and LF, and any other ISO control characters except for standard printable ASCII.
        return input.replaceAll("[\\r\\n\\x00-\\x1F\\x7F]+", " ");
    }
}
