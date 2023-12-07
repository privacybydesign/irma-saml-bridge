package nl.sidn.irma.saml_bridge.controller.test;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A servlet that tells the tester that the response has been received, but not
 * tested for validity.
 */
@Controller
@RequestMapping("/test/return")
public class ReturnTestController {

    @PostMapping(value = "")
    public void testReturn(
            HttpServletResponse response) throws IOException {
        response.setStatus(200);
        response.getWriter().write(
                "This is a placeholder page to which you have been redirected. No SAML response was verified. It is fine to see this page when testing.");
    }
}
