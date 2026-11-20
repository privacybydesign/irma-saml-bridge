package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// Counterpart of ConfigurationServiceTest.getConfigurationTest: the
// configuration files in the repository are read, by the name in
// CONFIG_PATH.
func TestLoadConfigFromRepository(t *testing.T) {
	cfg, err := loadConfig(env(map[string]string{"CONFIG_PATH": "./config.test.json"}))
	require.NoError(t, err)

	assert.Equal(t, "sidn-irma-saml-bridge", cfg.issuerName())
	assert.Equal(t, "localhost:8080", cfg.Host)
	assert.Equal(t, "/irma-saml-bridge", cfg.Postfix)
	assert.Equal(t, "./dev-keys/jwt.der", cfg.JWTPrivateKeyPath)
	require.NotNil(t, cfg.TestIrmaPrivateKeyPath)
	assert.Equal(t, "./dev-keys/irma-test.der", *cfg.TestIrmaPrivateKeyPath)
	assert.Equal(t, "./dev-keys/irma-test.pub.der", cfg.IrmaPublicKeyPath)
	assert.Equal(t, "./dev-keys/idp.crt", cfg.SAMLCertificatePath)
	assert.Equal(t, "./dev-keys/idp.der", cfg.SAMLPrivateKeyPath)
	assert.Equal(t, "./dev-keys/metadata", cfg.SAMLMetadataPath)
	assert.Equal(t, "http://", cfg.protocol())
	assert.Equal(t, 900*time.Second, cfg.requestTTL())
	assert.Equal(t, 900*time.Second, cfg.responseTTL())
	assert.Equal(t, [][][]string{{{"irma-demo.gemeente.personalData.fullname"}}}, cfg.DefaultCondiscon)
	assert.Equal(t, irmaPath{Host: "192.168.0.2:8089", IrmaServiceHost: "192.168.0.2:8089"}, *cfg.DefaultMap)
	assert.Equal(t, map[string]irmaPath{"test": {Host: "192.168.0.2:8089", IrmaServiceHost: "192.168.0.2:8089"}}, cfg.IrmaMapping)
	assert.Equal(t, "http://localhost:8080/irma-saml-bridge/request", cfg.constructURL("/request"))

	// Without SERVER_SERVLET_CONTEXT_PATH and SERVER_PORT the defaults of
	// the Java service apply.
	assert.Equal(t, "/irma-saml-bridge", cfg.contextPath)
	assert.Equal(t, ":8080", cfg.listenAddr)

	production, err := loadConfig(env(map[string]string{"CONFIG_PATH": "./config.default.json"}))
	require.NoError(t, err)
	assert.Nil(t, production.TestIrmaPrivateKeyPath)
	assert.Equal(t, "/irmademo", production.IrmaMapping["test"].Postfix)
}

// Counterpart of IrmaSamlBridgeApplicationTests.contextLoads: the service
// starts with config.test.json, the keys in dev-keys and the metadata in
// dev-keys/metadata, and serves.
func TestServerStartsWithRepositoryConfiguration(t *testing.T) {
	cfg, err := loadConfig(env(map[string]string{"CONFIG_PATH": "./config.test.json"}))
	require.NoError(t, err)

	srv, err := newServer(cfg)
	require.NoError(t, err)
	assert.Equal(t, 4, srv.registry.Len())

	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/irma-saml-bridge/actuator/health/readiness") //nolint:noctx // a test
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// With the dev keys, /test/assert makes the login the Java service
	// made, signed with a certificate that expired in 2022.
	resp, err = http.Get(ts.URL + "/irma-saml-bridge/test/assert") //nolint:noctx // a test
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Only what has no default. The file is found as ./config.json when
	// CONFIG_PATH is not set.
	require.NoError(t, os.WriteFile(path, []byte(`{
		"host": "bridge.example",
		"postfix": "/saml-bridge",
		"jwtPrivateKeyPath": "a", "irmaPublicKeyPath": "b", "samlCertificatePath": "c",
		"samlPrivateKeyPath": "d", "samlMetadataPath": "e",
		"defaultCondiscon": [[["pbdf.sidn-pbdf.email.email"]]],
		"defaultMap": {"host": "{spName}.bridge.example", "irmaServiceHost": "bridge.example", "postfix": "/{spName}"},
		"unknownKey": {"is": "ignored"}
	}`), 0o600))

	t.Chdir(dir)

	cfg, err := loadConfig(env(nil))
	require.NoError(t, err)

	// issuerName falls back to the host, https is on, and requests and
	// assertions live 360 seconds.
	assert.Equal(t, "bridge.example", cfg.issuerName())
	assert.Equal(t, "https://", cfg.protocol())
	assert.Equal(t, "https://bridge.example/saml-bridge/request", cfg.constructURL("/request"))
	assert.Equal(t, 360*time.Second, cfg.requestTTL())
	assert.Equal(t, 360*time.Second, cfg.responseTTL())
	assert.Nil(t, cfg.TestIrmaPrivateKeyPath)
	assert.False(t, cfg.IrmaServerTLSInsecureSkipVerify)

	// {spName} is filled in for the host and the postfix, not for the host
	// the bridge itself calls.
	assert.Equal(t, irmaPath{Host: "klant.bridge.example", IrmaServiceHost: "bridge.example", Postfix: "/klant"}, cfg.irmaPathFor("klant"))
}

func TestLoadConfigRejects(t *testing.T) {
	valid := `"host":"h","jwtPrivateKeyPath":"a","irmaPublicKeyPath":"b","samlCertificatePath":"c","samlPrivateKeyPath":"d","samlMetadataPath":"e",` +
		`"defaultCondiscon":[[["a.b.c.d"]]],"defaultMap":{"host":"h","irmaServiceHost":"h","postfix":""}`

	tests := map[string]struct {
		content string
		want    string
	}{
		"not JSON":                 {`not json`, "config.json"},
		"empty object":             {`{}`, "missing defaultCondiscon, defaultMap, host, irmaPublicKeyPath, jwtPrivateKeyPath, samlCertificatePath, samlMetadataPath, samlPrivateKeyPath"},
		"no default condiscon":     {strings.Replace(`{`+valid+`}`, `"defaultCondiscon":[[["a.b.c.d"]]],`, ``, 1), "missing defaultCondiscon"},
		"no default map":           {strings.Replace(`{`+valid+`}`, `,"defaultMap":{"host":"h","irmaServiceHost":"h","postfix":""}`, ``, 1), "missing defaultMap"},
		"condiscon of wrong shape": {strings.Replace(`{`+valid+`}`, `[[["a.b.c.d"]]]`, `["a.b.c.d"]`, 1), "config.json"},
		"zero ttl":                 {`{` + valid + `,"requestTtlInSec":0}`, "must be positive"},
		"negative ttl":             {`{` + valid + `,"responseTtlInSec":-5}`, "must be positive"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			_, err := loadConfig(env(map[string]string{"CONFIG_PATH": path}))
			require.ErrorContains(t, err, tt.want)
		})
	}

	_, err := loadConfig(env(map[string]string{"CONFIG_PATH": filepath.Join(t.TempDir(), "missing.json")}))
	require.ErrorContains(t, err, "configuration")

	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{`+valid+`}`), 0o600))

	_, err = loadConfig(env(map[string]string{"CONFIG_PATH": path}))
	require.NoError(t, err)

	_, err = loadConfig(env(map[string]string{"CONFIG_PATH": path, "SERVER_SERVLET_CONTEXT_PATH": "/{x}"}))
	require.ErrorContains(t, err, "SERVER_SERVLET_CONTEXT_PATH")

	_, err = loadConfig(env(map[string]string{"CONFIG_PATH": path, "SERVER_PORT": "http"}))
	require.ErrorContains(t, err, "SERVER_PORT")
}

func TestContextPathFromEnvironment(t *testing.T) {
	for value, want := range map[string]string{
		"":                  "/irma-saml-bridge",
		"/saml-bridge":      "/saml-bridge",
		"/saml-bridge/":     "/saml-bridge",
		"/a/b-c/d_e.f~g":    "/a/b-c/d_e.f~g",
		"/":                 "",
		"/irma-saml-bridge": "/irma-saml-bridge",
	} {
		got, err := contextPath(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
	}

	for _, value := range []string{"saml-bridge", "/a b", "/{id}", "/a//b", "/a?b", "/a/{b...}", "GET /a"} {
		_, err := contextPath(value)
		require.Error(t, err, value)
	}
}

func TestListenAddrFromEnvironment(t *testing.T) {
	for value, want := range map[string]string{"": ":8080", "8080": ":8080", "9090": ":9090"} {
		got, err := listenAddr(value)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	for _, value := range []string{"0", "65536", "-1", "eighty", "80 80"} {
		_, err := listenAddr(value)
		require.Error(t, err, value)
	}
}

// A service served at the root still answers.
func TestRootContextPath(t *testing.T) {
	root := "/"
	h := newHarness(t, harnessOptions{contextPath: &root, mutate: func(cfg map[string]any) {
		cfg["postfix"] = ""
	}})

	base := strings.TrimSuffix(h.base, "/")
	assert.Equal(t, http.StatusOK, h.get(base+"/actuator/health/liveness").status)
	assert.Equal(t, http.StatusOK, h.get(base+"/metadata").status)
}

// --- keys ---

// Counterpart of JwtUtilTest.derivedJwtPublicKeyMatchesKeyOnDisk: the key
// that verifies the assertion parameters belongs to dev-keys/jwt.der.
func TestKeysFromDevKeys(t *testing.T) {
	cfg, err := loadConfig(env(map[string]string{"CONFIG_PATH": "./config.test.json"}))
	require.NoError(t, err)

	k, err := loadKeys(cfg)
	require.NoError(t, err)

	onDisk, err := readPublicKey("./dev-keys/jwt.pub.der")
	require.NoError(t, err)
	assert.True(t, onDisk.Equal(&k.jwtPrivate.PublicKey))

	// The key pairs in dev-keys belong together.
	assert.True(t, k.irmaPublic.Equal(&k.testIrmaPrivate.PublicKey))
	assert.True(t, k.samlPrivate.PublicKey.Equal(k.samlCertificate.PublicKey))

	// A token signed with the dev key verifies with the key on disk, and
	// one signed with the test IRMA key with irmaPublicKey.
	signed, err := token.Sign(k.jwtPrivate, "sidn-irma-saml-bridge", "assert_parameters", "aparams", "value", time.Now())
	require.NoError(t, err)

	_, err = token.Verify(signed, onDisk, time.Now)
	require.NoError(t, err)

	result, err := token.SignClaims(k.testIrmaPrivate, "irmaserver", "disclosing_result", map[string]any{"proofStatus": "VALID"}, time.Now())
	require.NoError(t, err)

	claims, err := token.Verify(result, k.irmaPublic, time.Now)
	require.NoError(t, err)
	assert.Equal(t, "VALID", claims["proofStatus"])

	// Without a test IRMA key there is none.
	cfg.TestIrmaPrivateKeyPath = nil
	k, err = loadKeys(cfg)
	require.NoError(t, err)
	assert.Nil(t, k.testIrmaPrivate)
}

// The files the deployment makes with openssl are read whatever openssl
// version wrote them, and a PEM file is read as well.
func TestKeyFormats(t *testing.T) {
	dir := t.TempDir()
	key := testkeys.Key(t, "formats")

	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))

		return path
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pkcs1 := x509.MarshalPKCS1PrivateKey(key)

	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	for name, path := range map[string]string{
		"PKCS#8 DER (openssl 3)": write("pkcs8.der", pkcs8),
		"PKCS#1 DER (openssl 1)": write("pkcs1.der", pkcs1),
		"PKCS#8 PEM":             write("pkcs8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		"PKCS#1 PEM":             write("pkcs1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})),
	} {
		got, err := readPrivateKey(path)
		require.NoError(t, err, name)
		assert.True(t, got.Equal(key), name)
	}

	for name, path := range map[string]string{
		"SubjectPublicKeyInfo DER": write("pub.der", pkix),
		"SubjectPublicKeyInfo PEM": write("pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})),
		"PKCS#1 DER":               write("pub1.der", x509.MarshalPKCS1PublicKey(&key.PublicKey)),
	} {
		got, err := readPublicKey(path)
		require.NoError(t, err, name)
		assert.True(t, got.Equal(&key.PublicKey), name)
	}

	cert := testkeys.ValidCertificate(t, key, "formats")

	for name, path := range map[string]string{
		"PEM": write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		"DER": write("cert.der", cert.Raw),
	} {
		got, err := readCertificate(path)
		require.NoError(t, err, name)
		assert.True(t, got.Equal(cert), name)
	}

	// What is not the right kind of key is refused.
	garbage := write("garbage", []byte("not a key"))

	_, err = readPrivateKey(garbage)
	require.Error(t, err)

	_, err = readPublicKey(garbage)
	require.Error(t, err)

	_, err = readCertificate(garbage)
	require.Error(t, err)

	_, err = readPrivateKey(write("public-as-private", pkix))
	require.Error(t, err)

	_, err = readPublicKey(write("private-as-public", pkcs8))
	require.Error(t, err)

	_, err = readPrivateKey(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

// A configuration that cannot work stops the service at startup, with the
// key that is wrong in the message.
func TestServerRefusesToStartWithBrokenKeyMaterial(t *testing.T) {
	base := func(t *testing.T) *config {
		t.Helper()

		cfg, err := loadConfig(env(map[string]string{"CONFIG_PATH": "./config.test.json"}))
		require.NoError(t, err)

		return cfg
	}

	missing := filepath.Join(t.TempDir(), "missing")

	tests := map[string]struct {
		change func(cfg *config)
		want   string
	}{
		"jwt key missing":          {func(cfg *config) { cfg.JWTPrivateKeyPath = missing }, "jwtPrivateKeyPath"},
		"irma key missing":         {func(cfg *config) { cfg.IrmaPublicKeyPath = missing }, "irmaPublicKeyPath"},
		"irma key is a private":    {func(cfg *config) { cfg.IrmaPublicKeyPath = "./dev-keys/jwt.der" }, "irmaPublicKeyPath"},
		"certificate missing":      {func(cfg *config) { cfg.SAMLCertificatePath = missing }, "samlCertificatePath"},
		"saml key missing":         {func(cfg *config) { cfg.SAMLPrivateKeyPath = missing }, "samlPrivateKeyPath"},
		"test key missing":         {func(cfg *config) { cfg.TestIrmaPrivateKeyPath = &missing }, "testIrmaPrivateKeyPath"},
		"key not of certificate":   {func(cfg *config) { cfg.SAMLPrivateKeyPath = "./dev-keys/jwt.der" }, "does not belong"},
		"metadata directory gone":  {func(cfg *config) { cfg.SAMLMetadataPath = missing }, "metadata directory"},
		"metadata is not metadata": {func(cfg *config) { cfg.SAMLMetadataPath = "./samples" }, "metadata file"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := base(t)
			tt.change(cfg)

			_, err := newServer(cfg)
			require.ErrorContains(t, err, tt.want)
		})
	}
}
