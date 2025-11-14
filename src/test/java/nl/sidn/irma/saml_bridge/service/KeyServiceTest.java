package nl.sidn.irma.saml_bridge.service;

import nl.sidn.irma.saml_bridge.model.Configuration;
import nl.sidn.irma.saml_bridge.util.KeyReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for KeyService.
 */
@ExtendWith({SpringExtension.class, MockitoExtension.class})
class KeyServiceTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    ConfigurationService configurationService;

    @Mock
    KeyReader keyReader;

    private static KeyPair genRsaKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    @Test
    void initializes_all_fields_when_explicit_jwt_public_key_is_configured()
            throws Exception {
        // Arrange config paths
        final Configuration cfg = mock(Configuration.class);
        when(configurationService.getConfiguration()).thenReturn(cfg);

        final String jwtPriv = "/path/jwt.priv";
        final String jwtPub = "/path/jwt.pub";
        final String irmaPub = "/path/irma.pub";
        final String samlCert = "/path/saml.crt";
        final String samlPriv = "/path/saml.key";
        final String testIrmaPriv = "/path/irma-test.priv";

        when(cfg.getJwtPrivateKeyPath()).thenReturn(jwtPriv);
        when(cfg.getJwtPublicKeyPath()).thenReturn(jwtPub);
        when(cfg.getIrmaPublicKeyPath()).thenReturn(irmaPub);
        when(cfg.getSamlCertificatePath()).thenReturn(samlCert);
        when(cfg.getSamlPrivateKeyPath()).thenReturn(samlPriv);
        when(cfg.getTestIrmaPrivateKeyPath()).thenReturn(testIrmaPriv);

        // Arrange keys/cert returns
        final KeyPair jwtPair = genRsaKeyPair();
        final KeyPair irmaPair = genRsaKeyPair();
        final KeyPair samlPair = genRsaKeyPair();
        final X509Certificate mockCert = mock(X509Certificate.class);

        when(keyReader.getPrivate(jwtPriv)).thenReturn((RSAPrivateKey) jwtPair.getPrivate());
        when(keyReader.getPublic(jwtPub)).thenReturn((RSAPublicKey) jwtPair.getPublic());
        when(keyReader.getPublic(irmaPub)).thenReturn((RSAPublicKey) irmaPair.getPublic());
        when(keyReader.getCertificate(samlCert)).thenReturn(mockCert);
        when(keyReader.getPrivate(samlPriv)).thenReturn((RSAPrivateKey) samlPair.getPrivate());
        when(keyReader.getPrivate(testIrmaPriv)).thenReturn((RSAPrivateKey) irmaPair.getPrivate());

        // Act
        final KeyService service = new KeyService(configurationService, keyReader);

        // Assert: everything loaded as-is from KeyReader
        assertSame(jwtPair.getPrivate(), service.getJwtPrivateKey());
        assertEquals(((RSAPublicKey) jwtPair.getPublic()).getModulus(), service.getJwtPublicKey().getModulus());
        assertEquals(((RSAPublicKey) irmaPair.getPublic()).getModulus(), service.getIrmaPublicKey().getModulus());
        assertSame(mockCert, service.getSamlCertificate());
        assertSame(samlPair.getPrivate(), service.getSamlPrivateKey());
        assertSame(irmaPair.getPrivate(), service.getTestIrmaPrivateKey());

        // Verify calls hit the expected paths
        verify(keyReader).getPrivate(jwtPriv);
        verify(keyReader).getPublic(jwtPub);
        verify(keyReader).getPublic(irmaPub);
        verify(keyReader).getCertificate(samlCert);
        verify(keyReader).getPrivate(samlPriv);
        verify(keyReader).getPrivate(testIrmaPriv);
    }

    @Test
    void derives_jwt_public_key_from_private_when_no_public_path()
            throws Exception {
        final Configuration cfg = mock(Configuration.class);
        when(configurationService.getConfiguration()).thenReturn(cfg);

        final String jwtPriv = "/path/jwt.priv";
        final String irmaPub = "/path/irma.pub";
        final String samlCert = "/path/saml.crt";
        final String samlPriv = "/path/saml.key";

        when(cfg.getJwtPrivateKeyPath()).thenReturn(jwtPriv);
        when(cfg.getJwtPublicKeyPath()).thenReturn(null); // force derivation
        when(cfg.getIrmaPublicKeyPath()).thenReturn(irmaPub);
        when(cfg.getSamlCertificatePath()).thenReturn(samlCert);
        when(cfg.getSamlPrivateKeyPath()).thenReturn(samlPriv);
        when(cfg.getTestIrmaPrivateKeyPath()).thenReturn(null); // optional

        final KeyPair jwtPair = genRsaKeyPair();
        final KeyPair irmaPair = genRsaKeyPair();
        final KeyPair samlPair = genRsaKeyPair();
        final X509Certificate mockCert = mock(X509Certificate.class);

        when(keyReader.getPrivate(jwtPriv)).thenReturn((RSAPrivateKey) jwtPair.getPrivate());
        when(keyReader.getPublic(irmaPub)).thenReturn((RSAPublicKey) irmaPair.getPublic());
        when(keyReader.getCertificate(samlCert)).thenReturn(mockCert);
        when(keyReader.getPrivate(samlPriv)).thenReturn((RSAPrivateKey) samlPair.getPrivate());

        final KeyService service = new KeyService(configurationService, keyReader);

        final RSAPrivateCrtKey crt = (RSAPrivateCrtKey) jwtPair.getPrivate();
        assertEquals(crt.getModulus(), service.getJwtPublicKey().getModulus());
        assertEquals(crt.getPublicExponent(), service.getJwtPublicKey().getPublicExponent());
        assertNull(service.getTestIrmaPrivateKey(), "testIrmaPrivateKey should remain null when path is not set");
    }

    @Test
    void throws_when_no_public_path_and_private_is_not_crt()
            throws CertificateException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        final Configuration cfg = mock(Configuration.class);
        when(configurationService.getConfiguration()).thenReturn(cfg);

        final String jwtPriv = "/path/jwt.priv";

        when(cfg.getJwtPrivateKeyPath()).thenReturn(jwtPriv);
        when(cfg.getJwtPublicKeyPath()).thenReturn(null);

        final RSAPrivateKey nonCrtPrivate = new RSAPrivateKey() {
            @Override
            public BigInteger getPrivateExponent() {
                return BigInteger.ONE;
            }

            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }

            @Override
            public BigInteger getModulus() {
                return BigInteger.TWO;
            }
        };

        when(keyReader.getPrivate(jwtPriv)).thenReturn(nonCrtPrivate);

        final IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new KeyService(configurationService, keyReader));
        assertTrue(ex.getMessage().contains("No JWT public key configured"));
    }

    @Test
    void does_not_load_test_irma_private_when_path_missing() throws Exception {
        final Configuration cfg = mock(Configuration.class);
        when(configurationService.getConfiguration()).thenReturn(cfg);

        final String jwtPriv = "/path/jwt.priv";
        final String jwtPub = "/path/jwt.pub";
        final String irmaPub = "/path/irma.pub";
        final String samlCert = "/path/saml.crt";
        final String samlPriv = "/path/saml.key";

        when(cfg.getJwtPrivateKeyPath()).thenReturn(jwtPriv);
        when(cfg.getJwtPublicKeyPath()).thenReturn(jwtPub);
        when(cfg.getIrmaPublicKeyPath()).thenReturn(irmaPub);
        when(cfg.getSamlCertificatePath()).thenReturn(samlCert);
        when(cfg.getSamlPrivateKeyPath()).thenReturn(samlPriv);
        when(cfg.getTestIrmaPrivateKeyPath()).thenReturn(null);

        final KeyPair jwtPair = genRsaKeyPair();
        final KeyPair irmaPair = genRsaKeyPair();
        final KeyPair samlPair = genRsaKeyPair();
        final X509Certificate mockCert = mock(X509Certificate.class);

        when(keyReader.getPrivate(jwtPriv)).thenReturn((RSAPrivateKey) jwtPair.getPrivate());
        when(keyReader.getPublic(jwtPub)).thenReturn((RSAPublicKey) jwtPair.getPublic());
        when(keyReader.getPublic(irmaPub)).thenReturn((RSAPublicKey) irmaPair.getPublic());
        when(keyReader.getCertificate(samlCert)).thenReturn(mockCert);
        when(keyReader.getPrivate(samlPriv)).thenReturn((RSAPrivateKey) samlPair.getPrivate());

        final KeyService service = new KeyService(configurationService, keyReader);

        assertNull(service.getTestIrmaPrivateKey());
        verify(keyReader, never()).getPrivate(isNull()); // ensure not called with null
    }
}
