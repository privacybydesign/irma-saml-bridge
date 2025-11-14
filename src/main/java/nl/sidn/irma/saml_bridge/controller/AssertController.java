package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.exception.MalformedException;
import nl.sidn.irma.saml_bridge.model.*;
import nl.sidn.irma.saml_bridge.service.KeyService;
import nl.sidn.irma.saml_bridge.service.RedirectInstructionService;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/assert")
public class AssertController {

    private final ObjectMapper objectMapper;

    private final KeyService keyService;

    private final JwtUtil jwtUtil;

    private final RedirectInstructionService redirectInstructionService;

    public AssertController(final ObjectMapper objectMapper, final KeyService keyService, final JwtUtil jwtUtil, final RedirectInstructionService redirectInstructionService) {
        this.objectMapper = objectMapper;
        this.keyService = keyService;
        this.jwtUtil = jwtUtil;
        this.redirectInstructionService = redirectInstructionService;
    }

    @PostMapping(value = "", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public void report(@RequestBody(required = false) final AssertRequest assertRequest, final HttpServletResponse response) throws IOException {
        if (assertRequest == null || assertRequest.getParameters() == null || assertRequest.getParameters().isBlank() || assertRequest.getToken() == null || assertRequest.getToken().isBlank()) {
            response.setStatus(400);
            response.getWriter().write("Body must include non-empty 'parameters' and 'token' fields");
            return;
        }

        // Decode the IRMA response.
        final Jws<Claims> token = jwtUtil.getClaims(keyService.getIrmaPublicKey(), assertRequest.getToken());

        // Decode our pre-prepared set of assertion parameters.
        final Jws<Claims> parametersJws = jwtUtil.getClaims(keyService.getJwtPublicKey(), assertRequest.getParameters());

        // Unpack the IRMA response.
        final Disclosure disclosure;
        try {
            disclosure = Disclosure.fromJwt(token);
        } catch (final MalformedException e) {
            log.warn("action=\"assert-flow\", warning=\"Received malformed disclosure\"");
            response.setStatus(400);
            response.getWriter().write("Received malformed disclosure");
            return;
        }

        // Unpack the Assertion parameters.
        final AssertParameters assertParameters = AssertParameters.fromClaims(parametersJws.getPayload());

        // Verify that IRMA response is valid and present
        if (disclosure.getAttributes().isEmpty() || !"VALID".equals(disclosure.getProofStatus())) {
            log.warn("action=\"assert-flow\", warning=\"Expected valid proof and present attributes\"");
            response.setStatus(400);
            response.getWriter().write("Expected valid proof and present attributes");
            return;
        }

        // Verify that IRMA response matches our SAML request
        if (!disclosure.fulfillsCondiscon(objectMapper.readValue(assertParameters.getCondiscon(), String[][][].class))) {
            log.warn("action=\"assert-flow\", warning=\"The disclosure does not match the requested condiscon\"");
            response.setStatus(400);
            response.getWriter().write("The disclosure does not match the requested condiscon");
            return;
        }

        // Construct the set of instructions to the React applet.
        final RedirectInstruction ri;
        try {
            ri = this.redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS);
        } catch (final BridgeException e) {
            response.setStatus(e.getHttpStatusCode());
            response.getWriter().write(e.getMessage());
            return;
        }

        log.info("action=\"disclosedsuccesfully\", attributes=\"{}\", serviceprovider=\"{}\"", disclosure.getAttributes().keySet(), assertParameters.getSpName());

        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(ri));
    }
}
