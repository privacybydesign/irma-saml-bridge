package nl.sidn.irma.saml_bridge.controller.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.DecodingException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.AssertRequest;
import nl.sidn.irma.saml_bridge.model.RedirectInstruction;
import nl.sidn.irma.saml_bridge.model.RequestError;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Slf4j
@Controller
@RequestMapping("/test/errorassert")
public class ErrorAssertTestController {

    private static final String BASE_URL = "http://localhost:8080/irma-saml-bridge";

    private final JwtUtil jwtUtil;

    private final ObjectMapper objectMapper;

    public ErrorAssertTestController(
            final JwtUtil jwtUtil,
            final ObjectMapper objectMapper) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

    @PostMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public void testAssert(
            final HttpServletResponse httpServletResponse,
            @RequestBody(required = false) final RequestError requestError) throws IOException, DecodingException {

        constructTest(httpServletResponse, requestError, "/errorassert");
    }

    @PostMapping(value = "/abort", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public void testAssertAbort(
            final HttpServletResponse httpServletResponse,
            @RequestBody(required = false) final RequestError requestError) throws IOException, DecodingException {

        constructTest(httpServletResponse, requestError, "/errorassert/abort");
    }

    private void constructTest(
            final HttpServletResponse httpServletResponse,
            final RequestError requestError,
            final String endpointUrl) throws IOException, DecodingException {
        if (requestError != null) {
            log.info("Test Error Assert with requestError: {}", StringEscapeUtils.escapeJava(requestError.toString()));
        }

        final String ATTRIBUTE_KEY = "pbdf.gemeente.personalData.fullname";
        final String[][][] condiscon = {{{ATTRIBUTE_KEY}}};
        final String AUTHNREQUEST_ID = "0";
        final String RETURN_URL = "http://test";
        final String RELAY_STATE = "relay_state_test";
        final String ISSUER = "sidn-irma-saml-bridge";
        final String SP_NAME = "test";
        final AssertParameters assertParameters = AssertParameters.builder()
                .spName(SP_NAME)
                .requestId(AUTHNREQUEST_ID)
                .serviceUrl(RETURN_URL)
                .issuer(ISSUER)
                .condiscon(objectMapper.writeValueAsString(condiscon))
                .relayState(RELAY_STATE)
                .requestError(requestError)
                .build();

        final Map<String, Object> attr = new TreeMap<>();
        final String ATTRIBUTE_VALUE = "W.Geraedts";
        attr.put("rawvalue", ATTRIBUTE_VALUE);
        attr.put("id", ATTRIBUTE_KEY);
        attr.put("status", "PRESENT");

        final List<Map<String, Object>> con = new ArrayList<>();
        con.add(attr);

        final List<List<Map<String, Object>>> discon = new ArrayList<>();
        discon.add(con);

        final Map<String, Object> claims = new TreeMap<>();
        final String TOKEN = "0";
        claims.put("token", TOKEN);
        claims.put("status", "DONE");
        claims.put("type", "disclosing");
        claims.put("proofStatus", "VALID");
        claims.put("disclosed", discon);

        final AssertRequest arequest = new AssertRequest();
        arequest.setParameters(jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));
        arequest.setToken(this.jwtUtil.createTestIrmaJwtTokenWithClaims("irmaserver", "disclosing_result", claims));

        final HttpPost request = new HttpPost(String.format("%s" + endpointUrl, BASE_URL));
        request.setEntity(new StringEntity(objectMapper.writeValueAsString(arequest)));

        final HttpResponse response = HttpClientBuilder.create().build().execute(request);

        final RedirectInstruction redirectInstruction = objectMapper.readValue(response.getEntity().getContent(),
                RedirectInstruction.class);
        // decode SAML response so we can check the XML response
        if (redirectInstruction.getSamlResponse() != null) {
            final byte[] samlResponse = Base64Support.decode(redirectInstruction.getSamlResponse());
            redirectInstruction.setSamlResponse(new String(samlResponse));
        }
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(redirectInstruction));
    }
}
