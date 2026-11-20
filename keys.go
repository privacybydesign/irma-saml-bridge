package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
)

// keys is the key material of the bridge, read once at startup.
type keys struct {
	// jwtPrivate signs the session requests for the IRMA server and the
	// assertion parameters. Its public half verifies the latter.
	jwtPrivate *rsa.PrivateKey

	// irmaPublic verifies the session results of the IRMA server.
	irmaPublic *rsa.PublicKey

	// testIrmaPrivate plays the IRMA server for /test/assert. It is nil
	// unless testIrmaPrivateKeyPath is set, which it is not in production.
	testIrmaPrivate *rsa.PrivateKey

	samlPrivate     *rsa.PrivateKey
	samlCertificate *x509.Certificate
}

func loadKeys(cfg *config) (*keys, error) {
	var (
		k   keys
		err error
	)

	if k.jwtPrivate, err = readPrivateKey(cfg.JWTPrivateKeyPath); err != nil {
		return nil, fmt.Errorf("jwtPrivateKeyPath: %w", err)
	}

	if k.irmaPublic, err = readPublicKey(cfg.IrmaPublicKeyPath); err != nil {
		return nil, fmt.Errorf("irmaPublicKeyPath: %w", err)
	}

	if k.samlCertificate, err = readCertificate(cfg.SAMLCertificatePath); err != nil {
		return nil, fmt.Errorf("samlCertificatePath: %w", err)
	}

	if k.samlPrivate, err = readPrivateKey(cfg.SAMLPrivateKeyPath); err != nil {
		return nil, fmt.Errorf("samlPrivateKeyPath: %w", err)
	}

	if cfg.TestIrmaPrivateKeyPath != nil && *cfg.TestIrmaPrivateKeyPath != "" {
		if k.testIrmaPrivate, err = readPrivateKey(*cfg.TestIrmaPrivateKeyPath); err != nil {
			return nil, fmt.Errorf("testIrmaPrivateKeyPath: %w", err)
		}
	}

	return &k, nil
}

// readDER returns the DER bytes in a file. The Java service wanted DER; a
// PEM file is taken as well, so that a key does not have to be converted
// first.
func readDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from the configuration
	if err != nil {
		return nil, err
	}

	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes, nil
	}

	return data, nil
}

// readPrivateKey reads an RSA private key: PKCS#8, as the Java service
// needed it, or PKCS#1, which "openssl rsa -outform DER" wrote before
// OpenSSL 3.
func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	der, err := readDER(path)
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}

		return rsaKey, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, errors.New("not an RSA private key in PKCS#8 or PKCS#1 format")
	}

	return key, nil
}

// readPublicKey reads an RSA public key: SubjectPublicKeyInfo, as written by
// "openssl rsa -pubout", or PKCS#1.
func readPublicKey(path string) (*rsa.PublicKey, error) {
	der, err := readDER(path)
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}

		return rsaKey, nil
	}

	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, errors.New("not an RSA public key in SubjectPublicKeyInfo or PKCS#1 format")
	}

	return key, nil
}

// readCertificate reads an X.509 certificate in PEM or DER.
func readCertificate(path string) (*x509.Certificate, error) {
	der, err := readDER(path)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func sortedStrings(s []string) []string {
	sort.Strings(s)

	return s
}
