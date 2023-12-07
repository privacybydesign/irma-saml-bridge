package nl.sidn.irma.saml_bridge.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import nl.sidn.irma.saml_bridge.service.ConfigurationService;
import nl.sidn.irma.saml_bridge.service.KeyService;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.util.Map;

import static io.jsonwebtoken.Jwts.parserBuilder;

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

    public Jws<Claims> getClaims(Key key, String claims) {
        return parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(claims);
    }

    public String createJwtToken(String subject, String claimName, Object claim) {
        return Jwts.builder()
                .setIssuedAt(Date.from(Instant.now()))
                .setIssuer(this.configurationService.getConfiguration().getIssuerName())
                .setSubject(subject)
                .signWith(this.keyService.getJwtPrivateKey())
                .claim(claimName, claim)
                .compact();
    }

    public String createTestIrmaJwtTokenWithClaims(String issuer, String subject, Map<String, Object> claims) {
        return Jwts.builder()
                .setIssuedAt(Date.from(Instant.now()))
                .setIssuer(issuer)
                .setSubject(subject)
                .signWith(this.keyService.getTestIrmaPrivateKey())
                .setClaims(claims)
                .compact();
    }
}
