package nl.sidn.irma.saml_bridge.util;

import org.opensaml.security.x509.X509Support;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility class to read key material in various formats from disk.
 * 
 * See the README.md file on how to generate any of these files.
 */
@Service
public class KeyReader {
	/**
	 * Read a RSA private key in PKCS8 DER format from disk.
	 * 
	 * @param path
	 * @return A properly read RSAPrivateKey.
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public RSAPrivateKey getPrivate(String path)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(path));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPrivateKey) kf.generatePrivate(spec);
	}

	/**
	 * Read a RSA public key in PKCS8 DER format from disk.
	 * 
	 * @param path
	 * @return A properly read RSAPrivateKey.
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public RSAPublicKey getPublic(String path)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(path));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) kf.generatePublic(spec);
	}
	
	/**
	 * Read a RSA certificate in X509 CRT format from disk.
	 * 
	 * @param path
	 * @return A properly read RSAPrivateKey.
	 * @throws IOException
	 * @throws CertificateException 
	 */
	public X509Certificate getCertificate(String path) throws IOException, CertificateException {
		byte[] bytes = Files.readAllBytes(Paths.get(path));
		return X509Support.decodeCertificate(bytes);
	}
}
