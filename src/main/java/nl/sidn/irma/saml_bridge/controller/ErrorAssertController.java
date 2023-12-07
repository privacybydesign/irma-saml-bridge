package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.*;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.RedirectInstructionService;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/errorassert")
public class ErrorAssertController {

    private final ObjectMapper objectMapper;

    private final KeyService keyService;

    private final JwtUtil jwtUtil;

    private final RedirectInstructionService redirectInstructionService;

    public ErrorAssertController(
            ObjectMapper objectMapper,
            KeyService keyService,
            JwtUtil jwtUtil,
            RedirectInstructionService redirectInstructionService
    ) {
        this.objectMapper = objectMapper;
        this.keyService = keyService;
        this.jwtUtil = jwtUtil;
        this.redirectInstructionService = redirectInstructionService;
    }

    /**
     * Endpoint, who handles a general error from the frontend
     * @param request
     * @param response
     * @throws IOException
     */
    @PostMapping(value="", produces = MediaType.APPLICATION_JSON_VALUE)
    public void error(
            HttpServletRequest request,
            HttpServletResponse response

    ) throws IOException {
        handleError(request, response, null);
    }

    /**
     * Endpoint, who handles the abort from the frontend
     * @param request
     * @param response
     * @throws IOException
     */
    @PostMapping(value="/abort", produces = MediaType.APPLICATION_JSON_VALUE)
    public void errorAbort(
            HttpServletRequest request,
            HttpServletResponse response

    ) throws IOException {
        handleError(request, response, RequestError.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .message("The user cancelled.")
                .build());
    }

    private void handleError(
            HttpServletRequest request,
            HttpServletResponse response,
            RequestError requestError
    ) throws IOException {
        // We receive a JSON POST body, and parse it.
        AssertRequest assertRequest = objectMapper.readValue(request.getReader(), AssertRequest.class);

        // Decode our pre-prepared set of assertion parameters.
        Jws<Claims> parametersJws = jwtUtil.getClaims(keyService.getJwtPrivateKey(), assertRequest.getParameters());

        // Unpack the Assertion parameters.
        AssertParameters assertParameters = AssertParameters.fromClaims(parametersJws.getBody());
        if(requestError != null) {
            assertParameters.setRequestError(requestError);
        }

        //something went wrong in the frontend, we don't have a specific error
        if(assertParameters.getRequestError() == null) {
            assertParameters.setRequestError(RequestError.builder()
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .message("Something went wrong in the frontend")
                    .build());
        }

        // Construct the set of instructions to the React applet.
        RedirectInstruction ri;
        try {
            ri = this.redirectInstructionService.create(assertParameters, ResultStatus.FAILED);
        } catch (BridgeException e) {
            response.setStatus(e.getHttpStatusCode());
            response.getWriter().write(e.getMessage());
            return;
        }

        log.info("action=\"disclosederror\", serviceprovider=\"{}\"", assertParameters.getSpName());

        // Yield these instructions as a REST json body response.
        response.setContentType("application/json");
        response.setStatus(200);
        response.getWriter().write(objectMapper.writeValueAsString(ri));
    }
}
