package nl.sidn.irma.saml_bridge.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import nl.sidn.irma.saml_bridge.service.KeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Exercises the real jjwt sign/verify round trip (no mocks) to guard the 0.12 migration:
 * tokens are still signed with the private key and verified with the matching public key.
 */
@SpringBootTest
class JwtUtilTest {

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    KeyService keyService;

    @Autowired
    KeyReader keyReader;

    @Test
    void derivedJwtPublicKeyMatchesKeyOnDisk() throws Exception {
        RSAPublicKey onDisk = keyReader.getPublic("./dev-keys/jwt.pub.der");
        RSAPublicKey derived = keyService.getJwtPublicKey();

        assertEquals(onDisk.getModulus(), derived.getModulus());
        assertEquals(onDisk.getPublicExponent(), derived.getPublicExponent());
    }

    @Test
    void selfSignedTokenVerifiesWithDerivedPublicKey() {
        String token = jwtUtil.createJwtToken("assert_parameters", "aparams", "value");

        Jws<Claims> jws = jwtUtil.getClaims(keyService.getJwtPublicKey(), token);

        assertEquals("assert_parameters", jws.getPayload().getSubject());
        assertEquals("sidn-irma-saml-bridge", jws.getPayload().getIssuer());
        assertEquals("value", jws.getPayload().get("aparams"));
    }

    @Test
    void irmaTokenVerifiesWithIrmaPublicKey() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("proofStatus", "VALID");
        claims.put("token", "session-token");

        String token = jwtUtil.createTestIrmaJwtTokenWithClaims("irmaserver", "disclosing_result", claims);

        Jws<Claims> jws = jwtUtil.getClaims(keyService.getIrmaPublicKey(), token);

        assertEquals("VALID", jws.getPayload().get("proofStatus"));
        assertEquals("session-token", jws.getPayload().get("token"));
    }
}
