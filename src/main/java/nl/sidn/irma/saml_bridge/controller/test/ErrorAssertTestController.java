package nl.sidn.irma.saml_bridge.controller.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.DecodingException;
import nl.sidn.irma.saml_bridge.model.AssertParameters;
import nl.sidn.irma.saml_bridge.model.AssertRequest;
import nl.sidn.irma.saml_bridge.model.RedirectInstruction;
import nl.sidn.irma.saml_bridge.model.RequestError;
import nl.sidn.irma.saml_bridge.util.JwtUtil;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletResponse;
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
    private static String SP_NAME = "test";
    private static String AUTHNREQUEST_ID = "0";
    private static String RETURN_URL = "http://test";
    private static String ISSUER = "sidn-irma-saml-bridge";
    private static String RELAY_STATE = "relay_state_test";
    private static String ATTRIBUTE_KEY = "pbdf.gemeente.personalData.fullname";
    private static String ATTRIBUTE_VALUE = "W.Geraedts";
    private static String TOKEN = "0";

    private final JwtUtil jwtUtil;

    private final ObjectMapper objectMapper;

    public ErrorAssertTestController(
            JwtUtil jwtUtil,
            ObjectMapper objectMapper) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

    @PostMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public void testAssert(
            HttpServletResponse httpServletResponse,
            @RequestBody(required = false) RequestError requestError) throws IOException, DecodingException {

        constructTest(httpServletResponse, requestError, "/errorassert");
    }

    @PostMapping(value = "/abort", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public void testAssertAbort(
            HttpServletResponse httpServletResponse,
            @RequestBody(required = false) RequestError requestError) throws IOException, DecodingException {

        constructTest(httpServletResponse, requestError, "/errorassert/abort");
    }

    private void constructTest(
            HttpServletResponse httpServletResponse,
            RequestError requestError,
            String endpointUrl) throws IOException, DecodingException {
        if (requestError != null) {
            log.info("Test Error Assert with requestError: {}", requestError);
        }

        String[][][] condiscon = { { { ATTRIBUTE_KEY } } };

        AssertParameters assertParameters = AssertParameters.builder()
                .spName(SP_NAME)
                .requestId(AUTHNREQUEST_ID)
                .serviceUrl(RETURN_URL)
                .issuer(ISSUER)
                .condiscon(objectMapper.writeValueAsString(condiscon))
                .relayState(RELAY_STATE)
                .requestError(requestError)
                .build();

        Map<String, Object> attr = new TreeMap<>();
        attr.put("rawvalue", ATTRIBUTE_VALUE);
        attr.put("id", ATTRIBUTE_KEY);
        attr.put("status", "PRESENT");

        List<Map<String, Object>> con = new ArrayList<>();
        con.add(attr);

        List<List<Map<String, Object>>> discon = new ArrayList<>();
        discon.add(con);

        Map<String, Object> claims = new TreeMap<>();
        claims.put("token", TOKEN);
        claims.put("status", "DONE");
        claims.put("type", "disclosing");
        claims.put("proofStatus", "VALID");
        claims.put("disclosed", discon);

        AssertRequest arequest = new AssertRequest();
        arequest.setParameters(jwtUtil.createJwtToken("assert_parameters", "aparams", assertParameters.toTreeMap()));
        arequest.setToken(this.jwtUtil.createTestIrmaJwtTokenWithClaims("irmaserver", "disclosing_result", claims));

        HttpPost request = new HttpPost(String.format("%s" + endpointUrl, BASE_URL));
        request.setEntity(new StringEntity(objectMapper.writeValueAsString(arequest)));

        HttpResponse response = HttpClientBuilder.create().build().execute(request);

        RedirectInstruction redirectInstruction = objectMapper.readValue(response.getEntity().getContent(),
                RedirectInstruction.class);
        // decode SAML response so we can check the XML response
        if (redirectInstruction.getSamlResponse() != null) {
            byte[] samlResponse = Base64Support.decode(redirectInstruction.getSamlResponse());
            redirectInstruction.setSamlResponse(new String(samlResponse));
        }
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(redirectInstruction));
    }
}
