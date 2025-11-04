package nl.sidn.irma.saml_bridge.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.KeyService;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Map;

@Service
public class JwtUtil {
    private final ConfigurationService configurationService;

    private final KeyService keyService;

    public JwtUtil(
            ConfigurationService configurationService,
            KeyService keyService
    ) {
        this.configurationService = configurationService;
        this.keyService = keyService;
    }

    public Jws<Claims> getClaims(PublicKey key, String jwt) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt);
    }

    public String createJwtToken(String subject, String claimName, Object claim) {
        return Jwts.builder()
                .issuedAt(Date.from(Instant.now()))
                .issuer(this.configurationService.getConfiguration().getIssuerName())
                .subject(subject)
                .signWith(this.keyService.getJwtPrivateKey())
                .claim(claimName, claim)
                .compact();
    }

    public String createTestIrmaJwtTokenWithClaims(String issuer, String subject, Map<String, Object> claims) {
        return Jwts.builder()
                .issuedAt(Date.from(Instant.now()))
                .issuer(issuer)
                .subject(subject)
                .signWith(this.keyService.getTestIrmaPrivateKey())
                .claims(claims)
                .compact();
    }
}
