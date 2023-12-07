package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.model.ClientError;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/report")
public class ErrorReportController {

    private final ObjectMapper objectMapper;

    public ErrorReportController(
            ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
    }
    @PostMapping(value="")
    public void report(
            HttpServletRequest request,
            HttpServletResponse response

    ) throws IOException {
        ClientError error = objectMapper.readValue(request.getReader(), ClientError.class);

        log.warn("action=\"clientsideerror\", source=\"{}\", linenr=\"{}\", colnr=\"{}\", message=\"{}\"",
                limitString(error.getSource(), 50),
                error.getLineno(),
                error.getColno(),
                limitString(error.getMessage(), 256)
        );

        response.setStatus(200);
    }

    private static String limitString(String str, int length) {
        if (str == null) {
            return null;
        }

        if (str.length() > length) {
            return str.substring(0, length);
        }
        return str;
    }
}
