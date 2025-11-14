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
import java.util.regex.Pattern;

@Slf4j
@Controller
@RequestMapping("/report")
public class ErrorReportController {

    private static final Pattern UNSAFE =
            Pattern.compile("[\\p{Cc}\\p{Zl}\\p{Zp}\\u200B-\\u200D\\u2060\\uFEFF\\u202A-\\u202E]+");

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
     * Sanitize a string for safe logging by removing or replacing invisible and control characters
     * that could corrupt log output or enable log-forging attacks.
     * <p>
     * Specifically, this method replaces the following character classes and code points with a single space:
     * <ul>
     *   <li>All Unicode control characters ({@code \p{Cc}}), including ASCII control range {@code 0x00–0x1F} and {@code 0x7F}</li>
     *   <li>Unicode line and paragraph separators ({@code \p{Zl}}, {@code \p{Zp}})</li>
     *   <li>Zero-width and formatting characters such as {@code U+200B–U+200D}, {@code U+2060}, and {@code U+FEFF}</li>
     *   <li>Bidirectional text control marks ({@code U+202A–U+202E})</li>
     * </ul>
     * Runs of such characters are collapsed into a single space. Printable ASCII and normal visible
     * Unicode characters are preserved.
     * <p>
     * The returned string is safe for inclusion in structured log messages without introducing
     * unintended line breaks or invisible text manipulation.
     *
     * @param input the input string to sanitize (maybe {@code null})
     * @return a sanitized string with unsafe characters replaced by spaces, or {@code null} if input was {@code null}
     */
    private static String sanitizeForLog(final String input) {
        if (input == null) return null;
        String s = UNSAFE.matcher(input).replaceAll(" ");
        // collapse multiple spaces and trim ends
        s = s.replaceAll(" +", " ").trim();
        return s;
    }
}
