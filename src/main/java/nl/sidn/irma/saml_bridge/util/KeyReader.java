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
 * <p>
 * See the README.md file on how to generate any of these files.
 */
@Service
public class KeyReader {
    /**
     * Read a RSA private key in PKCS8 DER format from disk.
     *
     * @param path The path to the key file.
     * @return A properly read RSAPrivateKey.
     * @throws IOException              The IO exception is thrown when the file could not be read.
     * @throws InvalidKeySpecException  The invalid key spec exception is thrown when the key is malformed.
     * @throws NoSuchAlgorithmException The no such algorithm exception is thrown when the RSA algorithm is not supported.
     */
    public RSAPrivateKey getPrivate(final String path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        final byte[] keyBytes = Files.readAllBytes(Paths.get(path));

        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    /**
     * Read a RSA public key in PKCS8 DER format from disk.
     *
     * @param path The path to the key file.
     * @return A properly read RSAPrivateKey.
     * @throws IOException              The IO exception is thrown when the file could not be read.
     * @throws InvalidKeySpecException  The invalid key spec exception is thrown when the key is malformed.
     * @throws NoSuchAlgorithmException The no such algorithm exception is thrown when the RSA algorithm is not supported.
     */
    public RSAPublicKey getPublic(final String path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        final byte[] keyBytes = Files.readAllBytes(Paths.get(path));

        final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    /**
     * Read a RSA certificate in X509 CRT format from disk.
     *
     * @param path The path to the certificate file.
     * @return A properly read RSAPrivateKey.
     * @throws IOException          The IO exception is thrown when the file could not be read.
     * @throws CertificateException The certificate exception is thrown when the certificate is malformed.
     */
    public X509Certificate getCertificate(final String path) throws IOException, CertificateException {
        final byte[] bytes = Files.readAllBytes(Paths.get(path));
        return X509Support.decodeCertificate(bytes);
    }
}
