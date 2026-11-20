package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" //nolint:gosec // to make the SHA-1 signature that must be refused
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

const minimalRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>`

// devIdPKey is the public key of dev-keys/idp.crt, which the Java test
// service provider signed its requests with.
func devIdPKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	data, err := os.ReadFile("../../dev-keys/idp.crt")
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return cert.PublicKey.(*rsa.PublicKey)
}

// javaRedirects are query strings the Java service's /test/request made, one
// per request form, signed by OpenSAML.
func javaRedirects(t *testing.T) map[string]string {
	t.Helper()

	data, err := os.ReadFile("../../testdata/java/redirect-requests.txt")
	require.NoError(t, err)

	out := map[string]string{}

	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		name, query, ok := strings.Cut(line, " ")
		require.True(t, ok)

		out[name] = query
	}

	require.Len(t, out, 6)

	return out
}

func TestVerifyAcceptsRequestsSignedByOpenSAML(t *testing.T) {
	key := devIdPKey(t)

	for name, query := range javaRedirects(t) {
		t.Run(name, func(t *testing.T) {
			msg, err := DecodeRedirect(query)
			require.NoError(t, err)

			assert.True(t, msg.Signed())
			assert.Equal(t, SigAlgRSASHA256, msg.SigAlg())
			assert.Contains(t, string(msg.XML), "AuthnRequest")
			require.NoError(t, msg.Verify([]*rsa.PublicKey{key}))
		})
	}
}

func TestVerifyRejectsRequestSignedWithAnotherKey(t *testing.T) {
	msg, err := DecodeRedirect(javaRedirects(t)["default"])
	require.NoError(t, err)

	other := &testkeys.Key(t, "other").PublicKey
	require.ErrorIs(t, msg.Verify([]*rsa.PublicKey{other}), ErrSignature)

	// The right key among several is found.
	require.NoError(t, msg.Verify([]*rsa.PublicKey{other, devIdPKey(t)}))
}

func TestVerifyRejectsServiceProviderWithoutKeys(t *testing.T) {
	msg, err := DecodeRedirect(javaRedirects(t)["default"])
	require.NoError(t, err)

	require.ErrorIs(t, msg.Verify(nil), ErrSignature)
}

func TestEncodeRedirectRoundTrip(t *testing.T) {
	key := testkeys.Key(t, "sp")
	relay := "state with spaces & symbols=1"

	query, err := EncodeRedirect([]byte(minimalRequest), &relay, key)
	require.NoError(t, err)

	msg, err := DecodeRedirect(query)
	require.NoError(t, err)

	assert.Equal(t, minimalRequest, string(msg.XML))
	require.NotNil(t, msg.RelayState)
	assert.Equal(t, relay, *msg.RelayState)
	require.NoError(t, msg.Verify([]*rsa.PublicKey{&key.PublicKey}))
}

func TestDecodeRedirectWithoutRelayState(t *testing.T) {
	query, err := EncodeRedirect([]byte(minimalRequest), nil, testkeys.Key(t, "sp"))
	require.NoError(t, err)

	msg, err := DecodeRedirect(query)
	require.NoError(t, err)
	assert.Nil(t, msg.RelayState)
}

// Whatever is changed in the signed parameters, the signature no longer
// verifies.
func TestVerifyRejectsTamperedQuery(t *testing.T) {
	key := testkeys.Key(t, "sp")
	relay := "original"

	query, err := EncodeRedirect([]byte(minimalRequest), &relay, key)
	require.NoError(t, err)

	other := deflate(t, strings.Replace(minimalRequest, `ID="_1"`, `ID="_2"`, 1))

	tests := map[string]string{
		"other request":      replaceParam(t, query, "SAMLRequest", url.QueryEscape(other)),
		"other relay state":  replaceParam(t, query, "RelayState", "changed"),
		"relay state gone":   removeParam(query, "RelayState"),
		"other algorithm":    replaceParam(t, query, "SigAlg", url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")),
		"encoding changed":   strings.Replace(query, "%3D", "%3d", 1),
		"signature replaced": replaceParam(t, query, "Signature", url.QueryEscape(base64.StdEncoding.EncodeToString(make([]byte, 256)))),
	}

	for name, tampered := range tests {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, query, tampered)

			msg, err := DecodeRedirect(tampered)
			require.NoError(t, err)
			require.ErrorIs(t, msg.Verify([]*rsa.PublicKey{&key.PublicKey}), ErrSignature)
		})
	}
}

func TestVerifyRejectsUnsignedRequest(t *testing.T) {
	key := testkeys.Key(t, "sp")

	query, err := EncodeRedirect([]byte(minimalRequest), nil, key)
	require.NoError(t, err)

	tests := map[string]string{
		"no signature":    removeParam(query, "Signature"),
		"empty signature": replaceParam(t, query, "Signature", ""),
		"no algorithm":    removeParam(query, "SigAlg"),
		"nothing":         removeParam(removeParam(query, "Signature"), "SigAlg"),
	}

	for name, unsigned := range tests {
		t.Run(name, func(t *testing.T) {
			msg, err := DecodeRedirect(unsigned)
			require.NoError(t, err)
			require.ErrorIs(t, msg.Verify([]*rsa.PublicKey{&key.PublicKey}), ErrSignature)
		})
	}
}

// The Java service put no limit on SigAlg. A correct RSA-SHA1 signature is
// refused here.
func TestVerifyRejectsSHA1(t *testing.T) {
	key := testkeys.Key(t, "sp")

	const sha1Alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

	signed := "SAMLRequest=" + url.QueryEscape(deflate(t, minimalRequest)) + "&SigAlg=" + url.QueryEscape(sha1Alg)

	h := crypto.SHA1.New()
	h.Write([]byte(signed))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h.Sum(nil))
	require.NoError(t, err)

	msg, err := DecodeRedirect(signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)))
	require.NoError(t, err)

	err = msg.Verify([]*rsa.PublicKey{&key.PublicKey})
	require.ErrorIs(t, err, ErrSignature)
	assert.Contains(t, err.Error(), "not supported")
}

func TestDecodeRedirectRejects(t *testing.T) {
	key := testkeys.Key(t, "sp")

	valid, err := EncodeRedirect([]byte(minimalRequest), nil, key)
	require.NoError(t, err)

	request := url.QueryEscape(deflate(t, minimalRequest))

	tests := map[string]string{
		"empty query":           "",
		"no SAMLRequest":        "RelayState=x",
		"empty SAMLRequest":     "SAMLRequest=",
		"SAMLResponse only":     "SAMLResponse=" + request,
		"not base64":            "SAMLRequest=%21%21%21",
		"not deflated":          "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(minimalRequest))),
		"truncated deflate":     "SAMLRequest=AAAA",
		"bad percent encoding":  "SAMLRequest=%zz",
		"repeated SAMLRequest":  valid + "&SAMLRequest=" + request,
		"repeated Signature":    valid + "&Signature=AAAA",
		"repeated SigAlg":       valid + "&SigAlg=x",
		"repeated RelayState":   "RelayState=a&RelayState=b&SAMLRequest=" + request,
		"encoded name":          "SAML%52equest=" + request,
		"unsupported encoding":  "SAMLEncoding=urn%3Aother&SAMLRequest=" + request,
		"signature not base64":  "SAMLRequest=" + request + "&SigAlg=x&Signature=%21%21",
		"malformed other param": "SAMLRequest=" + request + "&%zz=1",
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeRedirect(query)
			require.ErrorIs(t, err, ErrDecode)
		})
	}
}

func TestDecodeRedirectAcceptsDeflateEncodingParameter(t *testing.T) {
	query := "SAMLEncoding=" + url.QueryEscape(encodingDeflate) + "&SAMLRequest=" + url.QueryEscape(deflate(t, minimalRequest)) + "&other=1"

	msg, err := DecodeRedirect(query)
	require.NoError(t, err)
	assert.Equal(t, minimalRequest, string(msg.XML))
	assert.False(t, msg.Signed())
}

// A small query that inflates to megabytes is cut off at the limit.
func TestDecodeRedirectRejectsDeflateBomb(t *testing.T) {
	bomb := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">` +
		strings.Repeat(" ", 16<<20) + `</samlp:AuthnRequest>`

	encoded := deflate(t, bomb)
	require.Less(t, len(encoded), 64<<10, "the bomb fits in a URL")

	_, err := DecodeRedirect("SAMLRequest=" + url.QueryEscape(encoded))
	require.ErrorIs(t, err, ErrDecode)
	require.ErrorIs(t, err, ErrXML)
}

func TestDecodeRedirectAcceptsRequestAtTheLimit(t *testing.T) {
	padding := MaxRequestXMLBytes - len(minimalRequest)
	exact := strings.Replace(minimalRequest, "/>", strings.Repeat(" ", padding)+"/>", 1)
	require.Len(t, exact, MaxRequestXMLBytes)

	_, err := DecodeRedirect("SAMLRequest=" + url.QueryEscape(deflate(t, exact)))
	require.NoError(t, err)

	_, err = DecodeRedirect("SAMLRequest=" + url.QueryEscape(deflate(t, exact+" ")))
	require.ErrorIs(t, err, ErrXML)
}

func deflate(t *testing.T, s string) string {
	t.Helper()

	var buf bytes.Buffer

	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)

	_, err = w.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func replaceParam(t *testing.T, query, name, rawValue string) string {
	t.Helper()

	parts := strings.Split(query, "&")
	for i, part := range parts {
		if strings.HasPrefix(part, name+"=") {
			parts[i] = name + "=" + rawValue

			return strings.Join(parts, "&")
		}
	}

	t.Fatalf("no parameter %s in %s", name, query)

	return ""
}

func removeParam(query, name string) string {
	var kept []string

	for part := range strings.SplitSeq(query, "&") {
		if !strings.HasPrefix(part, name+"=") {
			kept = append(kept, part)
		}
	}

	return strings.Join(kept, "&")
}
