package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

const testEntityID = "sidn-irma-saml-bridge"

// devIdP is the identity provider with the key and certificate from
// dev-keys, as the Java service was run to make testdata/java.
func devIdP(t *testing.T) *IdentityProvider {
	t.Helper()

	keyDER, err := os.ReadFile("../../dev-keys/idp.der")
	require.NoError(t, err)

	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	require.NoError(t, err)

	certPEM, err := os.ReadFile("../../dev-keys/idp.crt")
	require.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	idp, err := NewIdentityProvider(testEntityID, key.(*rsa.PrivateKey), cert)
	require.NoError(t, err)

	return idp
}

func newIdP(t *testing.T) *IdentityProvider {
	t.Helper()

	key := testkeys.Key(t, "idp")

	idp, err := NewIdentityProvider(testEntityID, key, testkeys.ValidCertificate(t, key, "idp"))
	require.NoError(t, err)

	return idp
}

// javaTestLogin is the fixed login behind the Java /test/assert endpoint.
func javaTestLogin(success bool, message string) ResponseParams {
	p := ResponseParams{
		RequestID:  "0",
		ServiceURL: "http://test",
		Audience:   testEntityID,
		Now:        time.Date(2026, 11, 20, 9, 22, 31, 458_000_000, time.UTC),
		Lifetime:   900 * time.Second,
	}

	if success {
		p.Success = true
		p.Attributes = map[string]string{"pbdf.gemeente.personalData.fullname": "W.Geraedts"}
		p.SessionToken = "0"
	} else {
		p.StatusMessage = message
	}

	return p
}

var (
	signatureElement = regexp.MustCompile(`(?s)<ds:Signature .*?</ds:Signature>`)
	randomIDValue    = regexp.MustCompile(`ID="_[0-9A-F]{40}"`)
	instantValue     = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z`)
	base64Content    = regexp.MustCompile(`(<ds:(?:DigestValue|SignatureValue|X509Certificate)>)[^<]*`)
	referenceURI     = regexp.MustCompile(`URI="#_[0-9A-F]{40}"`)
)

// normalize removes from a Response what differs between two runs: the
// signature, the random ID and the instants.
func normalize(xml string) string {
	xml = signatureElement.ReplaceAllString(xml, "<ds:Signature/>")
	xml = randomIDValue.ReplaceAllString(xml, `ID="_RANDOM"`)

	return instantValue.ReplaceAllString(xml, "INSTANT")
}

// signatureShape returns the Signature element without its values.
func signatureShape(t *testing.T, xml string) string {
	t.Helper()

	sig := signatureElement.FindString(xml)
	require.NotEmpty(t, sig)

	sig = base64Content.ReplaceAllString(sig, "$1")

	return referenceURI.ReplaceAllString(sig, `URI="#_RANDOM"`)
}

func signedXML(t *testing.T, idp *IdentityProvider, p ResponseParams) string {
	t.Helper()

	response := idp.NewResponse(p)
	require.NoError(t, idp.Sign(response))

	xml, err := response.XML()
	require.NoError(t, err)

	return string(xml)
}

// The Response is the one the Java service made for the same login, element
// for element and attribute for attribute. testdata/java holds what the Java
// image answered on /test/assert and /test/errorassert.
func TestResponseMatchesJava(t *testing.T) {
	tests := map[string]struct {
		file   string
		params ResponseParams
	}{
		"success":   {"response-success.xml", javaTestLogin(true, "")},
		"failed":    {"response-failed.xml", javaTestLogin(false, "Something went wrong in the frontend")},
		"cancelled": {"response-cancelled.xml", javaTestLogin(false, "The user cancelled.")},
	}

	idp := devIdP(t)

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			java, err := os.ReadFile("../../testdata/java/" + tt.file)
			require.NoError(t, err)

			got := signedXML(t, idp, tt.params)

			assert.Equal(t, normalize(string(java)), normalize(got))
			require.NoError(t, idp.Verify([]byte(got)))
		})
	}
}

// The signature is the one the Java service made. Each Response in
// testdata/java is stripped of its signature and signed again with the
// same key: the whole document must come out as the Java image wrote it.
// RSA PKCS#1 v1.5 signatures are deterministic, so this compares the
// digest, the canonical SignedInfo and the signature value, byte for byte.
func TestSignatureIsByteIdenticalToJava(t *testing.T) {
	idp := devIdP(t)

	for _, file := range []string{"response-success.xml", "response-failed.xml", "response-cancelled.xml"} {
		t.Run(file, func(t *testing.T) {
			java, err := os.ReadFile("../../testdata/java/" + file)
			require.NoError(t, err)

			doc, err := parseXML(java, maxMetadataBytes)
			require.NoError(t, err)

			root := doc.Root()
			sig := child(root, nsDSig, "Signature")
			require.NotNil(t, sig)
			root.RemoveChild(sig)

			response := &Response{el: root}
			if root.SelectAttr("xmlns:xsd") != nil {
				response.inclusivePrefixes = "xsd"
			}

			require.NoError(t, idp.Sign(response))

			got, err := response.XML()
			require.NoError(t, err)

			// etree writes a carriage return as &#xD;, the Java
			// serializer as &#13;. Both are the same character.
			assert.Equal(t, string(java), strings.ReplaceAll(string(got), "&#xD;", "&#13;"))
			require.NoError(t, idp.Verify(got))
		})
	}
}

// What the bridge signs has the shape of what the Java service signed: the
// same elements, attributes, algorithms and line breaks, and the xsd prefix
// as an InclusiveNamespaces prefix when the Response declares it.
func TestSignatureMatchesJava(t *testing.T) {
	idp := devIdP(t)

	for file, params := range map[string]ResponseParams{
		"response-success.xml":   javaTestLogin(true, ""),
		"response-failed.xml":    javaTestLogin(false, "x"),
		"response-cancelled.xml": javaTestLogin(false, "y"),
	} {
		java, err := os.ReadFile("../../testdata/java/" + file)
		require.NoError(t, err)

		got := signedXML(t, idp, params)
		assert.Equal(t, signatureShape(t, string(java)), signatureShape(t, got), file)
	}

	success := signedXML(t, idp, javaTestLogin(true, ""))
	assert.Contains(t, success, `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">`+
		`<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xsd"/></ds:Transform>`)

	failed := signedXML(t, idp, javaTestLogin(false, "x"))
	assert.NotContains(t, failed, "InclusiveNamespaces")
}

// A Response is signed once.
func TestSignTwiceFails(t *testing.T) {
	idp := newIdP(t)

	response := idp.NewResponse(javaTestLogin(true, ""))
	require.NoError(t, idp.Sign(response))
	require.Error(t, idp.Sign(response))

	xml, err := response.XML()
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(xml), "<ds:Signature "))
	require.NoError(t, idp.Verify(xml))
}

func TestResponseSuccessContent(t *testing.T) {
	idp := newIdP(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.FixedZone("CET", 3600))

	xml := signedXML(t, idp, ResponseParams{
		RequestID:  "_request",
		ServiceURL: "https://sp.example/acs",
		Audience:   "https://sp.example/metadata",
		Now:        now,
		Lifetime:   360 * time.Second,
		Success:    true,
		Attributes: map[string]string{
			"pbdf.sidn-pbdf.mobilenumber.mobilenumber": "+31612345678",
			"pbdf.sidn-pbdf.email.email":               "user@example.com",
		},
		SessionToken: "9zxuWKwL5KGLKr4uerws",
	})

	for _, want := range []string{
		`<?xml version="1.0" encoding="UTF-8"?><saml2p:Response `,
		`Destination="https://sp.example/acs"`,
		`InResponseTo="_request"`,
		// Instants are UTC with milliseconds.
		`IssueInstant="2026-03-01T11:00:00.000Z"`,
		`<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">sidn-irma-saml-bridge</saml2:Issuer><ds:Signature `,
		`<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`,
		// The assertion ID is the session token in hexadecimal, which
		// makes it a valid ID although the token starts with a digit.
		`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_397A7875574B774C354B474C4B72347565727773" `,
		// The NameID is the value of the first attribute by identifier.
		`<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user@example.com</saml2:NameID>`,
		`<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`,
		`<saml2:SubjectConfirmationData InResponseTo="_request" NotOnOrAfter="2026-03-01T11:06:00.000Z" Recipient="https://sp.example/acs"/>`,
		`<saml2:Conditions NotBefore="2026-03-01T11:00:00.000Z" NotOnOrAfter="2026-03-01T11:06:00.000Z">`,
		`<saml2:Audience>https://sp.example/metadata</saml2:Audience>`,
		`<saml2:AuthnStatement AuthnInstant="2026-03-01T11:00:00.000Z">`,
		`urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`,
	} {
		assert.Contains(t, xml, want)
	}

	// Attributes are ordered by identifier.
	email := strings.Index(xml, `<saml2:Attribute Name="pbdf.sidn-pbdf.email.email"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">user@example.com</saml2:AttributeValue>`)
	mobile := strings.Index(xml, `<saml2:Attribute Name="pbdf.sidn-pbdf.mobilenumber.mobilenumber">`)
	assert.Positive(t, email)
	assert.Greater(t, mobile, email)

	// The Response is signed; the assertion has no signature of its own.
	assert.Equal(t, 1, strings.Count(xml, "<ds:Signature "))
	assert.Less(t, strings.Index(xml, "<ds:Signature "), strings.Index(xml, "<saml2:Assertion "))

	// The prefix xsi:type refers to stays declared in what is sent.
	assert.Contains(t, xml, `xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)

	require.NoError(t, idp.Verify([]byte(xml)))
}

func TestResponseFailedContent(t *testing.T) {
	idp := newIdP(t)

	xml := signedXML(t, idp, ResponseParams{
		RequestID:     "_request",
		ServiceURL:    "https://sp.example/acs",
		Audience:      "https://sp.example/metadata",
		Now:           time.Now(),
		Lifetime:      time.Minute,
		StatusMessage: `IRMA said <no> & "left"`,
		// Never part of a failed Response.
		Attributes: map[string]string{"a.b.c.d": "secret"},
	})

	assert.Contains(t, xml, `<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">`+
		`<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></saml2p:StatusCode>`+
		`<saml2p:StatusMessage>IRMA said &lt;no&gt; &amp; "left"</saml2p:StatusMessage></saml2p:Status></saml2p:Response>`)
	assert.NotContains(t, xml, "Assertion")
	assert.NotContains(t, xml, "secret")
	assert.NotContains(t, xml, "xmlns:xsd")
	require.NoError(t, idp.Verify([]byte(xml)))
}

// An error on the page that could not read the request has no request to
// answer: no InResponseTo, no Destination, and an empty message.
func TestResponseFailedWithoutRequest(t *testing.T) {
	idp := newIdP(t)

	xml := signedXML(t, idp, ResponseParams{Now: time.Now(), Lifetime: time.Minute})

	assert.NotContains(t, xml, "InResponseTo")
	assert.NotContains(t, xml, "Destination")
	assert.Contains(t, xml, `<saml2p:StatusMessage/>`)
	require.NoError(t, idp.Verify([]byte(xml)))
}

func TestResponseWithoutAttributesHasNoNameID(t *testing.T) {
	idp := newIdP(t)

	p := javaTestLogin(true, "")
	p.Attributes = nil

	xml := signedXML(t, idp, p)

	assert.NotContains(t, xml, "NameID")
	assert.Contains(t, xml, "<saml2:AttributeStatement/>")
	assert.Contains(t, xml, "<saml2:SubjectConfirmation ")
	require.NoError(t, idp.Verify([]byte(xml)))
}

func TestResponseWithoutSessionTokenGetsRandomAssertionID(t *testing.T) {
	idp := newIdP(t)

	p := javaTestLogin(true, "")
	p.SessionToken = ""

	id := regexp.MustCompile(`<saml2:Assertion xmlns:saml2="[^"]+" ID="(_[0-9A-F]{40})"`)

	first := id.FindStringSubmatch(signedXML(t, idp, p))
	second := id.FindStringSubmatch(signedXML(t, idp, p))

	require.Len(t, first, 2)
	require.Len(t, second, 2)
	assert.NotEqual(t, first[1], second[1])
}

func TestResponseIDsAreRandomAndValidXMLIDs(t *testing.T) {
	idp := newIdP(t)
	id := regexp.MustCompile(`<saml2p:Response [^>]*\bID="([^"]+)"`)
	seen := map[string]bool{}

	for range 50 {
		m := id.FindStringSubmatch(signedXML(t, idp, javaTestLogin(false, "")))
		require.Len(t, m, 2)
		assert.Regexp(t, `^_[0-9A-F]{40}$`, m[1])
		assert.False(t, seen[m[1]])

		seen[m[1]] = true
	}
}

// Whatever the user's attributes contain, the Response that is sent still
// carries a signature that verifies. A carriage return is the classic way to
// break it: unescaped, an XML parser turns it into a line feed.
func TestSignatureSurvivesAwkwardValues(t *testing.T) {
	idp := newIdP(t)

	values := map[string]string{
		"markup":           `<script>alert("x")</script> & 'quotes'`,
		"carriage return":  "line one\r\nline two\rline three",
		"tabs and spaces":  "\t leading and trailing \t ",
		"unicode":          "Zoë Çelik, 山田太郎, José 🙂",
		"cdata end":        "]]> and <![CDATA[",
		"entity lookalike": "&amp; &#13; &xxe;",
		"empty":            "",
		"long":             strings.Repeat("a b ", 5000),
	}

	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			p := javaTestLogin(true, "")
			p.Attributes = map[string]string{"a.b.c.d": value, "a.b.c.e": "second"}
			p.RequestID = `_id"with<odd>&chars` + "\t"
			p.ServiceURL = "https://sp.example/acs?a=1&b=<2>"

			xml := signedXML(t, idp, p)
			require.NoError(t, idp.Verify([]byte(xml)))

			// What a service provider reads back is what was disclosed.
			doc, err := parseXML([]byte(xml), maxMetadataBytes)
			require.NoError(t, err)

			statement := child(child(doc.Root(), nsAssertion, "Assertion"), nsAssertion, "AttributeStatement")
			first := statement.ChildElements()[0]
			assert.Equal(t, value, child(first, nsAssertion, "AttributeValue").Text())

			destination, _ := attr(doc.Root(), "Destination")
			assert.Equal(t, p.ServiceURL, destination)

			inResponseTo, _ := attr(doc.Root(), "InResponseTo")
			assert.Equal(t, p.RequestID, inResponseTo)
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	idp := newIdP(t)

	response := idp.NewResponse(javaTestLogin(true, ""))
	unsigned, err := response.XML()
	require.NoError(t, err)

	signed := signedXML(t, idp, javaTestLogin(true, ""))

	otherKey := testkeys.Key(t, "other")
	other, err := NewIdentityProvider(testEntityID, otherKey, testkeys.ValidCertificate(t, otherKey, "other"))
	require.NoError(t, err)

	tests := map[string]string{
		"unsigned":             string(unsigned),
		"changed attribute":    strings.Replace(signed, "W.Geraedts</saml2:AttributeValue>", "Someone Else</saml2:AttributeValue>", 1),
		"changed name id":      strings.Replace(signed, ">W.Geraedts</saml2:NameID>", ">admin</saml2:NameID>", 1),
		"changed destination":  strings.Replace(signed, `Destination="http://test"`, `Destination="http://attacker.example"`, 1),
		"changed audience":     strings.Replace(signed, "<saml2:Audience>sidn-irma-saml-bridge", "<saml2:Audience>other-sp", 1),
		"changed status":       strings.Replace(signed, "status:Success", "status:Responder", 1),
		"signed by another":    signedXML(t, other, javaTestLogin(true, "")),
		"not a response":       `<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		"not XML":              "nonsense",
		"doctype":              `<!DOCTYPE r [<!ENTITY e "x">]>` + strings.TrimPrefix(signed, `<?xml version="1.0" encoding="UTF-8"?>`),
		"signature value gone": regexp.MustCompile(`<ds:SignatureValue>[^<]*`).ReplaceAllString(signed, "<ds:SignatureValue>"),
	}

	for name, xml := range tests {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, signed, xml)
			require.Error(t, idp.Verify([]byte(xml)))
		})
	}
}

// The certificate in dev-keys expired in 2022. The Java service kept
// signing with an expired certificate, and so does the bridge: the dates in
// the certificate are for the service provider to judge.
func TestSignAndVerifyWithExpiredCertificate(t *testing.T) {
	idp := devIdP(t)
	require.True(t, time.Now().After(idp.cert.NotAfter), "dev-keys/idp.crt is expected to be expired")

	require.NoError(t, idp.Verify([]byte(signedXML(t, idp, javaTestLogin(true, "")))))
}

func TestNewIdentityProviderRejectsMismatchedKey(t *testing.T) {
	key := testkeys.Key(t, "idp")
	cert := testkeys.ValidCertificate(t, testkeys.Key(t, "other"), "other")

	_, err := NewIdentityProvider(testEntityID, key, cert)
	require.ErrorContains(t, err, "does not belong")

	_, err = NewIdentityProvider(testEntityID, key, ecCertificate(t))
	require.ErrorContains(t, err, "RSA")
}

// The metadata is byte for byte what the Java service published with the
// same configuration (config.test.json and dev-keys).
func TestMetadataMatchesJava(t *testing.T) {
	idp := devIdP(t)

	want, err := os.ReadFile("../../testdata/java/idp-metadata.xml")
	require.NoError(t, err)

	got, err := idp.Metadata("http://localhost:8080/irma-saml-bridge/request")
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))

	want, err = os.ReadFile("../../testdata/java/test-sp-metadata.xml")
	require.NoError(t, err)

	got, err = idp.TestSPMetadata("http://localhost:8080/irma-saml-bridge/test/return", "http://localhost:8080/irma-saml-bridge/test/metadata")
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

// The metadata of the test service provider is metadata the bridge itself
// accepts: that is how the test service provider is registered.
func TestTestSPMetadataIsReadableAsServiceProvider(t *testing.T) {
	idp := newIdP(t)

	data, err := idp.TestSPMetadata("https://bridge.example/saml-bridge/test/return", "https://bridge.example/saml-bridge/test/metadata")
	require.NoError(t, err)

	sps, err := ParseMetadata(data)
	require.NoError(t, err)
	require.Len(t, sps, 1)

	assert.Equal(t, testEntityID, sps[0].EntityID)
	assert.Equal(t, "https://bridge.example/saml-bridge/test/return", sps[0].RedirectACS())
	require.Len(t, sps[0].SigningKeys, 1)
	assert.True(t, sps[0].SigningKeys[0].Equal(idp.cert.PublicKey))
}

func TestMetadataEscapesValues(t *testing.T) {
	key := testkeys.Key(t, "idp")

	idp, err := NewIdentityProvider(`https://idp.example/?a=1&b="2"<3>`, key, testkeys.ValidCertificate(t, key, "idp"))
	require.NoError(t, err)

	data, err := idp.Metadata("https://idp.example/request?x=1&y=2")
	require.NoError(t, err)

	doc, err := parseXML(data, maxMetadataBytes)
	require.NoError(t, err)

	entityID, _ := attr(doc.Root(), "entityID")
	assert.Equal(t, `https://idp.example/?a=1&b="2"<3>`, entityID)
}

func TestTestRequestForms(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		request TestRequest
		check   func(t *testing.T, req *AuthnRequest)
	}{
		"default": {
			TestRequest{},
			func(t *testing.T, req *AuthnRequest) {
				t.Helper()
				assert.Empty(t, req.Attributes)
				assert.Nil(t, req.NameIDPolicyFormat)
			},
		},
		"attributes": {
			TestRequest{Attributes: []string{"a.b.c.d", "a.b.c.e"}},
			func(t *testing.T, req *AuthnRequest) {
				t.Helper()
				assert.Equal(t, []ExtensionAttribute{{Name: "a.b.c.d", Requested: true}, {Name: "a.b.c.e", Requested: true}}, req.Attributes)
			},
		},
		"condiscon": {
			TestRequest{CondisconName: "signicat:param:condiscon", Condiscon: `[[["a.b.c.d"]]]`},
			func(t *testing.T, req *AuthnRequest) {
				t.Helper()
				assert.Equal(t, []ExtensionAttribute{{
					Name: "signicat:param:condiscon", Requested: true,
					Values: []ExtensionValue{{String: true, Text: `[[["a.b.c.d"]]]`}},
				}}, req.Attributes)
			},
		},
		"attribute": {
			TestRequest{AttributeCondiscon: `[[["a.b.c.d"]]]`},
			func(t *testing.T, req *AuthnRequest) {
				t.Helper()
				assert.Equal(t, []ExtensionAttribute{{
					Name:   "condiscon",
					Values: []ExtensionValue{{String: true, Text: `[[["a.b.c.d"]]]`}},
				}}, req.Attributes)
			},
		},
		"name id policy": {
			TestRequest{NameIDPolicyFormat: `[[["a.b.c.d"]]]`},
			func(t *testing.T, req *AuthnRequest) {
				t.Helper()
				require.NotNil(t, req.NameIDPolicyFormat)
				assert.JSONEq(t, `[[["a.b.c.d"]]]`, *req.NameIDPolicyFormat)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.request.Issuer = "test-sp"
			tt.request.IssueInstant = now

			xml, err := tt.request.AuthnRequestXML()
			require.NoError(t, err)

			req, err := ParseAuthnRequest(xml)
			require.NoError(t, err)

			assert.Equal(t, "test-sp", req.Issuer)
			assert.True(t, now.Equal(req.IssueInstant))
			assert.Regexp(t, `^_[0-9A-F]{40}$`, req.ID)
			tt.check(t, req)
		})
	}
}
