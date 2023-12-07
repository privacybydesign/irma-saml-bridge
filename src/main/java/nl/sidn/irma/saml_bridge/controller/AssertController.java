package nl.sidn.irma.saml_bridge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Controller
@RequestMapping("/assert")
public class AssertController {

    private final ObjectMapper objectMapper;

    private final KeyService keyService;

    private final JwtUtil jwtUtil;

    private final RedirectInstructionService redirectInstructionService;

    public AssertController(
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

    @PostMapping(value="", produces = MediaType.APPLICATION_JSON_VALUE)
    public void report(
            HttpServletRequest request,
            HttpServletResponse response

    ) throws IOException {
        // We receive a JSON POST body, and parse it.
        AssertRequest arequest = objectMapper.readValue(request.getReader(), AssertRequest.class);

        // Decode the IRMA response.
        Jws<Claims> token = jwtUtil.getClaims(keyService.getIrmaPublicKey(), arequest.getToken());

        // Decode our pre-prepared set of assertion parameters.
        Jws<Claims> parametersJws = jwtUtil.getClaims(keyService.getJwtPrivateKey(), arequest.getParameters());

        // Unpack the IRMA response.
        Disclosure disclosure;
        try {
            disclosure = Disclosure.fromJwt(token);
        } catch (MalformedException e) {
            log.warn("action=\"assert-flow\", warning=\"Received malformed disclosure\"");
            response.setStatus(400);
            response.getWriter().write("Received malformed disclosure");
            return;
        }

        // Unpack the Assertion parameters.
        AssertParameters assertParameters = AssertParameters.fromClaims(parametersJws.getBody());

        // Verify that IRMA response is valid and present
        if (disclosure.getAttributes().isEmpty() || !"VALID".equals(disclosure.getProofStatus())) {
            log.warn("action=\"assert-flow\", warning=\"Expected valid proof and present attributes\"");
            response.setStatus(401);
            response.getWriter().write("Expected valid proof and present attributes");
            return;
        }

        // Verify that IRMA response matches our SAML request
        if (!disclosure.fulfillsCondiscon(objectMapper.readValue(assertParameters.getCondiscon(), String[][][].class))) {
            log.warn("action=\"assert-flow\", warning=\"The disclosure does not match the requested condiscon\"");
            response.setStatus(401);
            response.getWriter().write("The disclosure does not match the requested condiscon");
            return;
        }

        // Construct the set of instructions to the React applet.
        RedirectInstruction ri;
        try {
            ri = this.redirectInstructionService.create(assertParameters, disclosure, ResultStatus.SUCCESS);
        } catch (BridgeException e) {
            response.setStatus(e.getHttpStatusCode());
            response.getWriter().write(e.getMessage());
            return;
        }

        log.info("action=\"disclosedsuccesfully\", attributes=\"{}\", serviceprovider=\"{}\"", disclosure.getAttributes().keySet(), assertParameters.getSpName());

        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(ri));
    }
}
