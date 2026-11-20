// Package testkeys makes RSA keys and certificates for tests. Nothing in the
// service imports it.
package testkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	mu    sync.Mutex
	cache = map[string]*rsa.PrivateKey{}
)

// Key returns a 2048 bit RSA key. The same name gives the same key for the
// whole test binary, so a key is generated once.
func Key(tb testing.TB, name string) *rsa.PrivateKey {
	tb.Helper()

	mu.Lock()
	defer mu.Unlock()

	if key, ok := cache[name]; ok {
		return key
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}

	cache[name] = key

	return key
}

// Certificate returns a self-signed certificate for key, valid between the
// two times.
func Certificate(tb testing.TB, key *rsa.PrivateKey, commonName string, notBefore, notAfter time.Time) *x509.Certificate {
	tb.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}

	return cert
}

// ValidCertificate returns a self-signed certificate that is valid now.
func ValidCertificate(tb testing.TB, key *rsa.PrivateKey, commonName string) *x509.Certificate {
	tb.Helper()

	now := time.Now()

	return Certificate(tb, key, commonName, now.Add(-time.Hour), now.Add(24*time.Hour))
}

// WritePKCS8 writes key as PKCS#8 DER, the format the Java service read.
func WritePKCS8(tb testing.TB, path string, key *rsa.PrivateKey) {
	tb.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}

	write(tb, path, der)
}

// WritePublicKey writes the public half of key as SubjectPublicKeyInfo DER.
func WritePublicKey(tb testing.TB, path string, key *rsa.PrivateKey) {
	tb.Helper()

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}

	write(tb, path, der)
}

// WriteCertificate writes cert as PEM.
func WriteCertificate(tb testing.TB, path string, cert *x509.Certificate) {
	tb.Helper()

	write(tb, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func write(tb testing.TB, path string, data []byte) {
	tb.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatal(err)
	}
}
