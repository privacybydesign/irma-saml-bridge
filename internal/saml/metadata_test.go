package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func spMetadata(entityAttrs, roleAttrs, body string) string {
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ` +
		`entityID="https://sp.example/metadata" ` + entityAttrs + `>` +
		`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" ` + roleAttrs + `>` + body +
		`</md:SPSSODescriptor></md:EntityDescriptor>`
}

func keyDescriptor(use string, certs ...*x509.Certificate) string {
	var data strings.Builder
	for _, cert := range certs {
		data.WriteString(`<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(cert.Raw) + `</ds:X509Certificate>`)
	}

	if use != "" {
		use = ` use="` + use + `"`
	}

	return `<md:KeyDescriptor` + use + `><ds:KeyInfo><ds:X509Data>` + data.String() + `</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
}

func acs(binding, location string) string {
	return `<md:AssertionConsumerService Binding="` + binding + `" Location="` + location + `" index="0"/>`
}

// The metadata files that ship in dev-keys/metadata are read as they are.
func TestLoadRegistryReadsDevKeysMetadata(t *testing.T) {
	registry, err := LoadRegistry("../../dev-keys/metadata")
	require.NoError(t, err)
	require.Equal(t, 4, registry.Len())

	const post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	tests := []struct {
		entityID string
		redirect string
		acs      []string
	}{
		{
			entityID: "https://broker-a.irmaconnect.nl/broker/authn/saml",
			redirect: "https://broker-a.irmaconnect.nl/broker/authn/saml/acs",
			acs:      []string{"https://broker-a.irmaconnect.nl/broker/authn/saml/acs"},
		},
		{
			entityID: "sidn1.cib.pre.connectis.com-broker-irma",
			redirect: "https://sidn1.cib.pre.connectis.com/broker/acs",
			acs:      []string{"https://sidn1.cib.pre.connectis.com/broker/acs"},
		},
		{
			entityID: "sidn-irma-saml-bridge",
			redirect: "http://localhost:8080/irma-saml-bridge/test/return",
			acs:      []string{"http://localhost:8080/irma-saml-bridge/test/return"},
		},
		{
			// SAMLtest has no HTTP-Redirect endpoint.
			entityID: "https://samltest.id/saml/sp",
			redirect: "",
			acs:      []string{"https://samltest.id/Shibboleth.sso/SAML2/POST", "https://samltest.id/Shibboleth.sso/SAML2/Artifact"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.entityID, func(t *testing.T) {
			sp, ok := registry.Lookup(tt.entityID, testNow)
			require.True(t, ok)

			// One signing key each. The certificates of the brokers
			// expired years ago and still count: a key is trusted because
			// it is in the metadata. SAMLtest's encryption key is left out.
			assert.Len(t, sp.SigningKeys, 1)
			assert.Equal(t, tt.redirect, sp.RedirectACS())

			for _, url := range tt.acs {
				assert.True(t, sp.HasACS(url), url)
			}

			assert.False(t, sp.HasACS("https://attacker.example.com/steal"))
			assert.False(t, sp.HasACS(""))
		})
	}

	signicat, _ := registry.Lookup("https://broker-a.irmaconnect.nl/broker/authn/saml", testNow)
	assert.Contains(t, signicat.ACS, Endpoint{Binding: post, Location: "https://broker-a.irmaconnect.nl/broker/authn/saml/acs"})

	_, ok := registry.Lookup("https://unknown.example", testNow)
	assert.False(t, ok)
}

func TestLoadRegistrySkipsHiddenEntriesAndDirectories(t *testing.T) {
	dir := t.TempDir()
	cert := testkeys.ValidCertificate(t, testkeys.Key(t, "sp"), "sp")

	// What a mounted config map looks like: the files are links into a
	// hidden directory.
	hidden := filepath.Join(dir, "..2026_11_20")
	require.NoError(t, os.Mkdir(hidden, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(hidden, "sp.xml"), []byte(spMetadata(``, ``, keyDescriptor("signing", cert))), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(hidden, "sp.xml"), filepath.Join(dir, "sp.xml")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitkeep"), nil, 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdirectory"), 0o750))

	registry, err := LoadRegistry(dir)
	require.NoError(t, err)
	assert.Equal(t, 1, registry.Len())
}

func TestLoadRegistryFailsOnUnreadableMetadata(t *testing.T) {
	tests := map[string]string{
		"not XML":           "this is not metadata",
		"other root":        `<other xmlns="urn:other"/>`,
		"no entityID":       `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`,
		"doctype":           `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + spMetadata(``, ``, ``),
		"bad certificate":   spMetadata(``, ``, `<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`),
		"bad validUntil":    spMetadata(`validUntil="soon"`, ``, ``),
		"empty aggregate":   `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`,
		"SAML 1 descriptor": `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:1.0:metadata" entityID="x"/>`,
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "sp.xml"), []byte(content), 0o600))

			_, err := LoadRegistry(dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "sp.xml")
		})
	}

	_, err := LoadRegistry(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestParseMetadataKeys(t *testing.T) {
	signing := testkeys.ValidCertificate(t, testkeys.Key(t, "signing"), "signing")
	unspecified := testkeys.ValidCertificate(t, testkeys.Key(t, "unspecified"), "unspecified")
	encryption := testkeys.ValidCertificate(t, testkeys.Key(t, "encryption"), "encryption")
	chain := testkeys.ValidCertificate(t, testkeys.Key(t, "chain"), "chain")
	expired := testkeys.Certificate(t, testkeys.Key(t, "expired"), "expired", testNow.AddDate(-5, 0, 0), testNow.AddDate(-4, 0, 0))

	sps, err := ParseMetadata([]byte(spMetadata(``, ``,
		keyDescriptor("signing", signing, chain)+
			keyDescriptor("", unspecified)+
			keyDescriptor("encryption", encryption)+
			keyDescriptor("signing", expired)+
			keyDescriptor("signing", ecCertificate(t)))))
	require.NoError(t, err)
	require.Len(t, sps, 1)

	keys := sps[0].SigningKeys
	require.Len(t, keys, 3)

	// Signing and unspecified use count; the second certificate of an
	// X509Data, the encryption key and the EC key do not; an expired
	// certificate does.
	assert.True(t, keys[0].Equal(signing.PublicKey))
	assert.True(t, keys[1].Equal(unspecified.PublicKey))
	assert.True(t, keys[2].Equal(expired.PublicKey))
}

func TestParseMetadataIgnoresOtherProtocolsAndRoles(t *testing.T) {
	cert := testkeys.ValidCertificate(t, testkeys.Key(t, "sp"), "sp")

	xml := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="sp">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + keyDescriptor("signing", cert) + `</md:IDPSSODescriptor>` +
		`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">` + keyDescriptor("signing", cert) +
		acs(BindingRedirect, "https://saml1.example/acs") + `</md:SPSSODescriptor>` +
		`</md:EntityDescriptor>`

	sps, err := ParseMetadata([]byte(xml))
	require.NoError(t, err)
	require.Len(t, sps, 1)

	// An identity provider, or a SAML 1.1 service provider, has no key the
	// bridge accepts requests with and no place to send a Response.
	assert.Empty(t, sps[0].SigningKeys)
	assert.Empty(t, sps[0].ACS)
	assert.Empty(t, sps[0].RedirectACS())
	assert.False(t, sps[0].HasACS("https://saml1.example/acs"))
}

func TestParseMetadataEndpoints(t *testing.T) {
	const post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	sps, err := ParseMetadata([]byte(spMetadata(``, ``,
		acs(post, "https://sp.example/post")+acs(BindingRedirect, "https://sp.example/redirect")+acs(BindingRedirect, "https://sp.example/second"))))
	require.NoError(t, err)

	sp := sps[0]
	assert.Equal(t, "https://sp.example/redirect", sp.RedirectACS())
	assert.True(t, sp.HasACS("https://sp.example/post"))
	assert.True(t, sp.HasACS("https://sp.example/second"))

	// The match is exact.
	for _, url := range []string{"https://sp.example/post/", "https://sp.example/POST", "https://sp.example/post?x=1", "http://sp.example/post", "https://sp.example/pos"} {
		assert.False(t, sp.HasACS(url), url)
	}
}

func TestLookupHonoursValidUntil(t *testing.T) {
	sps, err := ParseMetadata([]byte(spMetadata(`validUntil="2026-11-20T12:00:00Z"`, ``, ``)))
	require.NoError(t, err)

	registry := NewRegistry(sps...)

	_, ok := registry.Lookup("https://sp.example/metadata", testNow.Add(-time.Second))
	assert.True(t, ok)

	_, ok = registry.Lookup("https://sp.example/metadata", testNow)
	assert.False(t, ok, "metadata is no longer valid at validUntil")
}

func TestParseMetadataAggregate(t *testing.T) {
	entity := func(id, attrs string) string {
		return `<md:EntityDescriptor entityID="` + id + `" ` + attrs + `/>`
	}

	xml := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2026-12-01T00:00:00Z">` +
		entity("one", ``) +
		`<md:EntitiesDescriptor>` + entity("two", `validUntil="2026-11-21T00:00:00Z"`) + entity("three", `validUntil="2027-01-01T00:00:00Z"`) + `</md:EntitiesDescriptor>` +
		`</md:EntitiesDescriptor>`

	sps, err := ParseMetadata([]byte(xml))
	require.NoError(t, err)
	require.Len(t, sps, 3)

	registry := NewRegistry(sps...)

	// The earliest validUntil on the way down applies.
	expectValidUntil := map[string]time.Time{
		"one":   time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		"two":   time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC),
		"three": time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	}

	for id, until := range expectValidUntil {
		_, ok := registry.Lookup(id, until.Add(-time.Second))
		assert.True(t, ok, id)

		_, ok = registry.Lookup(id, until)
		assert.False(t, ok, id)
	}
}

func TestNewRegistryKeepsFirstOfDuplicates(t *testing.T) {
	first := &ServiceProvider{EntityID: "sp", ACS: []Endpoint{{Binding: BindingRedirect, Location: "https://first.example"}}}
	second := &ServiceProvider{EntityID: "sp", ACS: []Endpoint{{Binding: BindingRedirect, Location: "https://second.example"}}}

	registry := NewRegistry(first, second)
	require.Equal(t, 1, registry.Len())

	sp, ok := registry.Lookup("sp", testNow)
	require.True(t, ok)
	assert.Equal(t, "https://first.example", sp.RedirectACS())
}

func ecCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec"},
		NotBefore:    testNow.Add(-time.Hour),
		NotAfter:     testNow.Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}
