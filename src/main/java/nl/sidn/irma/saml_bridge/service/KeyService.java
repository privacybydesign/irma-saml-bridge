package nl.sidn.irma.saml_bridge.service;

import lombok.Getter;
import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.util.KeyReader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * A service that reads all certificates and keys from disk and keeps them in memory.
 * <p>
 * Must be configured using system environment variables.
 */
@Getter
@Service
public class KeyService {
    /**
     * Private key which we use to sign JWT messages
     */
    private RSAPrivateKey jwtPrivateKey;

    /**
     * Public key which we use to verify JWT messages
     */
    private RSAPublicKey jwtPublicKey;

    /**
     * Private key used to simulate the IRMA go instance, might be NULL (i.e. in production)
     */
    private RSAPrivateKey testIrmaPrivateKey;

    /**
     * Public key of the IRMA go instance we will communicate with, used to verify their messages
     */
    private RSAPublicKey irmaPublicKey;

    /**
     * Certificate used to sign SAML responses and assertions
     */
    private X509Certificate samlCertificate;

    /**
     * Private key used to sign SAML responses and assertions
     */
    private RSAPrivateKey samlPrivateKey;

    private final ConfigurationService configurationService;

    private final KeyReader keyReader;

    public KeyService(
            ConfigurationService configurationService,
            KeyReader keyReader
    ) throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        this.configurationService = configurationService;
        this.keyReader = keyReader;
        initialize();
    }

    /**
     * Read all files from disk.
     * Will fail when any file is not configured, unavailable or malformed.
     *
     * @throws InvalidKeySpecException  The invalid key spec exception is thrown when a key is malformed.
     * @throws NoSuchAlgorithmException The no such algorithm exception is thrown when the RSA algorithm is not supported.
     * @throws IOException              The IO exception is thrown when a file could not be read.
     * @throws CertificateException     The certificate exception is thrown when a certificate is malformed.
     */
    private void initialize() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, CertificateException {
        Configuration conf = configurationService.getConfiguration();

        this.jwtPrivateKey = keyReader.getPrivate(conf.getJwtPrivateKeyPath());

        if (conf.getJwtPublicKeyPath() != null) {
            this.jwtPublicKey = keyReader.getPublic(conf.getJwtPublicKeyPath());
        } else if (jwtPrivateKey instanceof RSAPrivateCrtKey crt) {
            var spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
            this.jwtPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        } else {
            throw new IllegalStateException("No JWT public key configured and cannot derive from private key.");
        }

        this.irmaPublicKey = keyReader.getPublic(conf.getIrmaPublicKeyPath());
        this.samlCertificate = keyReader.getCertificate(conf.getSamlCertificatePath());
        this.samlPrivateKey = keyReader.getPrivate(conf.getSamlPrivateKeyPath());

        String irmaPrivateKeyTest = conf.getTestIrmaPrivateKeyPath();
        if (irmaPrivateKeyTest != null) {
            this.testIrmaPrivateKey = keyReader.getPrivate(irmaPrivateKeyTest);
        }
    }
}
