package nl.sidn.irma.saml_bridge;

import nl.sidn.irma.saml_bridge.model.*;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class Fixtures {

    private static final String TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    @SafeVarargs
    public static RedirectInstruction redirectInstruction(Consumer<RedirectInstruction>... configuratie) {
        RedirectInstruction redirectInstruction = RedirectInstruction.builder()
                .relayState("relayState")
                .serviceUrl("http://dummy")
                .samlResponse("SAML Response")
                .build();

        Stream.of(configuratie).forEach(c -> c.accept(redirectInstruction));
        return redirectInstruction;
    }

    @SafeVarargs
    public static AssertParameters assertParameters(Consumer<AssertParameters>... configuratie) {
        AssertParameters assertParameters = AssertParameters.builder()
                .spName("spName")
                .requestId("requestId")
                .serviceUrl("http://dummy")
                .issuer("issuer")
                .condiscon("repackedCondiscon")
                .relayState("RelayState")
                .build();

        Stream.of(configuratie).forEach(c -> c.accept(assertParameters));
        return assertParameters;
    }

    @SafeVarargs
    public static AssertRequest assertRequest(Consumer<AssertRequest>... configuratie) {
        AssertRequest assertRequest = new AssertRequest();
        assertRequest.setParameters("parameters");
        assertRequest.setToken(TOKEN);
        Stream.of(configuratie).forEach(c -> c.accept(assertRequest));
        return assertRequest;
    }

    @SafeVarargs
    public static Disclosure disclosure(Consumer<Disclosure>... configuratie) {
        Disclosure disclosure = new Disclosure();
        Map<String, String> attributes = new TreeMap<>();
        attributes.put("test", "test");
        disclosure.setAttributes(attributes);
        disclosure.setProofStatus("ProofStatus");
        disclosure.setToken(TOKEN);
        Stream.of(configuratie).forEach(c -> c.accept(disclosure));
        return disclosure;
    }

    @SafeVarargs
    public static Configuration configuration(Consumer<Configuration>... configuratie) {
        Configuration configuration = new Configuration();
        configuration.setHost("localhost:8080");
        configuration.setDefaultCondiscon(new String[][][] {{{"irma-demo.gemeente.personalData.fullname"}}});
        configuration.setPostfix("");
        configuration.setDefaultMap(irmaPath());
        configuration.setIrmaMapping(Collections.singletonMap("irmaPath", irmaPath()));
        configuration.setIssuerName("sidn-irma-saml-bridge");
        configuration.setIrmaPublicKeyPath("./dev-keys/irma-test.pub.der");
        configuration.setJwtPrivateKeyPath("./dev-keys/jwt.der");
        configuration.setHttpsUsed(false);
        configuration.setSamlCertificatePath("./dev-keys/idp.crt");
        configuration.setSamlMetadataPath("./dev-keys/metadata");
        configuration.setSamlPrivateKeyPath("./dev-keys/idp.der");
        configuration.setTestIrmaPrivateKeyPath("./dev-keys/irma-test.der");
        Stream.of(configuratie).forEach(c -> c.accept(configuration));
        return configuration;
    }

    @SafeVarargs
    public static IrmaPath irmaPath(Consumer<IrmaPath>... configuratie) {
        IrmaPath irmaPath = new IrmaPath();
        irmaPath.setHost("localhost:8080");
        irmaPath.setPostfix("");
        Stream.of(configuratie).forEach(c -> c.accept(irmaPath));
        return irmaPath;

    }
    public static List<List<Map<String, Object>>> defaultDiscloseClaims(String status) {
        List<List<Map<String, Object>>> disclosedClaim = new ArrayList<>();
        List<Map<String, Object>> disclosedClaim1 = new ArrayList<>();
        Map<String, Object> disclosedClaimMap = new TreeMap<>();
        disclosedClaimMap.put("id", "12345");
        disclosedClaimMap.put("status", status);
        disclosedClaimMap.put("rawvalue", "rawvalue");
        disclosedClaim1.add(disclosedClaimMap);
        disclosedClaim.add(disclosedClaim1);

        return disclosedClaim;
    }

}
