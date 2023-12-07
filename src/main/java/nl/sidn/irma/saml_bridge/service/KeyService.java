package nl.sidn.irma.saml_bridge.service;

import lombok.Getter;
import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.util.KeyReader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * A service that reads all certificates and keys from disk and keeps them in memory.
 * 
 * Must be configured using system environment variables.
 */
@Getter
@Service
public class KeyService {
	/** Private key which we use to sign JWT messages */
	private RSAPrivateKey jwtPrivateKey;

	/** Private key used to simulate the IRMA go instance, might be NULL (i.e. in production) */
	private RSAPrivateKey testIrmaPrivateKey;
	
	/** Public key of the IRMA go instance we will communicate with, used to verify their messages */
	private RSAPublicKey irmaPublicKey;

	/** Certificate used to sign SAML responses and assertions */
	private X509Certificate samlCertificate;

	/** Private key used to sign SAML responses and assertions */
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
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CertificateException
	 */
	private void initialize() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, CertificateException {
		Configuration conf = configurationService.getConfiguration();

		this.jwtPrivateKey = keyReader.getPrivate(conf.getJwtPrivateKeyPath());
		this.irmaPublicKey = keyReader.getPublic(conf.getIrmaPublicKeyPath());
		this.samlCertificate = keyReader.getCertificate(conf.getSamlCertificatePath());
		this.samlPrivateKey = keyReader.getPrivate(conf.getSamlPrivateKeyPath());

		String irmaPrivateKeyTest = conf.getTestIrmaPrivateKeyPath();
		if (irmaPrivateKeyTest != null) {
			this.testIrmaPrivateKey = keyReader.getPrivate(irmaPrivateKeyTest);
		}
	}
}
