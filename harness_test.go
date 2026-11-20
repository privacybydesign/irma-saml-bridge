package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

// The harness runs the whole bridge against a service provider and an IRMA
// server that are played by the test. Everything listens on the loopback
// interface; no network and no Docker are needed.

const (
	testContextPath = "/saml-bridge"
	testIssuerName  = "https://bridge.example/metadata"
	spEntityID      = "https://sp.example/metadata"
	spACS           = "https://sp.example/acs"
	irmaPostfix     = "/irma"

	defaultAttribute = "irma-demo.sidn-pbdf.email.email"
)

type harness struct {
	t   *testing.T
	srv *server

	// base is the URL of the bridge, context path included.
	base string

	irma *fakeIrma
	sp   *saml2.SAMLServiceProvider

	spKey   *rsa.PrivateKey
	idpCert *x509.Certificate
}

type harnessOptions struct {
	// mutate changes the configuration before it is written.
	mutate func(cfg map[string]any)

	// metadata adds metadata files next to that of the service provider.
	metadata map[string]string

	// spMetadata replaces the metadata of the service provider.
	spMetadata func(generated []byte) []byte

	// contextPath is the value of SERVER_SERVLET_CONTEXT_PATH.
	contextPath *string

	// registerTestSP puts the metadata of the bridge's built-in test
	// service provider in the metadata directory, as an operator does who
	// wants to use /test/request.
	registerTestSP bool
}

type keyStore struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (k keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.cert.Raw, nil }

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	h := &harness{t: t}
	dir := t.TempDir()

	// The bridge has to know its own address before it exists, so the
	// listener comes first and the handler is filled in later.
	var handler http.Handler

	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(bridge.Close)

	bridgeHost := strings.TrimPrefix(bridge.URL, "http://")

	jwtKey := testkeys.Key(t, "jwt")
	irmaKey := testkeys.Key(t, "irma")
	idpKey := testkeys.Key(t, "idp")
	h.spKey = testkeys.Key(t, "sp")
	h.idpCert = testkeys.ValidCertificate(t, idpKey, "idp")

	h.irma = newFakeIrma(t, irmaKey, &jwtKey.PublicKey)

	testkeys.WritePKCS8(t, filepath.Join(dir, "jwt.der"), jwtKey)
	testkeys.WritePKCS8(t, filepath.Join(dir, "irma-test.der"), irmaKey)
	testkeys.WritePublicKey(t, filepath.Join(dir, "irma.pub.der"), irmaKey)
	testkeys.WritePKCS8(t, filepath.Join(dir, "idp.der"), idpKey)
	testkeys.WriteCertificate(t, filepath.Join(dir, "idp.crt"), h.idpCert)

	contextPath := testContextPath
	if opts.contextPath != nil {
		contextPath = *opts.contextPath
	}

	postfix := contextPath
	if contextPath == "" {
		postfix = defaultContextPath
	}

	h.base = bridge.URL + postfix

	h.sp = &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      h.base + "/request",
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      testIssuerName,
		ServiceProviderIssuer:       spEntityID,
		AssertionConsumerServiceURL: spACS,
		AudienceURI:                 spEntityID,
		SignAuthnRequests:           true,
		SignAuthnRequestsAlgorithm:  dsig.RSASHA256SignatureMethod,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{h.idpCert}},
		SPKeyStore:                  keyStore{key: h.spKey, cert: testkeys.ValidCertificate(t, h.spKey, "sp")},
	}

	metadataDir := filepath.Join(dir, "metadata")
	require.NoError(t, os.Mkdir(metadataDir, 0o750))

	descriptor, err := h.sp.Metadata()
	require.NoError(t, err)

	spMetadata, err := xml.Marshal(descriptor)
	require.NoError(t, err)

	if opts.spMetadata != nil {
		spMetadata = opts.spMetadata(spMetadata)
	}

	require.NoError(t, os.WriteFile(filepath.Join(metadataDir, "sp.xml"), spMetadata, 0o600))

	for name, content := range opts.metadata {
		require.NoError(t, os.WriteFile(filepath.Join(metadataDir, name), []byte(content), 0o600))
	}

	if opts.registerTestSP {
		idp, err := saml.NewIdentityProvider(testIssuerName, idpKey, h.idpCert)
		require.NoError(t, err)

		testSP, err := idp.TestSPMetadata(h.base+"/test/return", h.base+"/test/metadata")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(metadataDir, "test.xml"), testSP, 0o600))
	}

	cfg := map[string]any{
		"issuerName":             testIssuerName,
		"host":                   bridgeHost,
		"postfix":                postfix,
		"jwtPrivateKeyPath":      filepath.Join(dir, "jwt.der"),
		"testIrmaPrivateKeyPath": filepath.Join(dir, "irma-test.der"),
		"irmaPublicKeyPath":      filepath.Join(dir, "irma.pub.der"),
		"samlCertificatePath":    filepath.Join(dir, "idp.crt"),
		"samlPrivateKeyPath":     filepath.Join(dir, "idp.der"),
		"samlMetadataPath":       metadataDir,
		"httpsUsed":              false,
		"requestTtlInSec":        900,
		"responseTtlInSec":       600,
		"defaultCondiscon":       [][][]string{{{defaultAttribute}}},
		"defaultMap": map[string]any{
			"host":            "{spName}.irma.example",
			"irmaServiceHost": h.irma.host,
			"postfix":         irmaPostfix,
		},
		"irmaMapping": map[string]any{
			"mapped": map[string]any{
				"host":            "irma.mapped.example",
				"irmaServiceHost": h.irma.host,
				"postfix":         "/{spName}",
			},
		},
	}

	if opts.mutate != nil {
		opts.mutate(cfg)
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	configPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(configPath, data, 0o600))

	loaded, err := loadConfig(func(name string) string {
		switch name {
		case envConfigPath:
			return configPath
		case envContextPath:
			if opts.contextPath != nil && *opts.contextPath == "" {
				return ""
			}

			return contextPath
		}

		return ""
	})
	require.NoError(t, err)

	h.srv, err = newServer(loaded)
	require.NoError(t, err)

	handler = h.srv.routes()

	return h
}

// --- the service provider ---

// authnRequest is a request the service provider is about to send.
type authnRequest struct {
	id  string
	url string
}

// redirect builds a signed AuthnRequest with gosaml2 and returns the URL the
// browser is sent to.
func (h *harness) redirect(relayState string) authnRequest {
	h.t.Helper()

	doc, err := h.sp.BuildAuthRequestDocumentNoSig()
	require.NoError(h.t, err)

	target, err := h.sp.BuildAuthURLRedirect(relayState, doc)
	require.NoError(h.t, err)

	return authnRequest{id: doc.Root().SelectAttrValue("ID", ""), url: target}
}

// customRequest signs an AuthnRequest the test wrote itself, with the key of
// the service provider.
func (h *harness) customRequest(xmlDoc string, relayState *string) string {
	h.t.Helper()

	return h.signedBy(h.spKey, xmlDoc, relayState)
}

func (h *harness) signedBy(key *rsa.PrivateKey, xmlDoc string, relayState *string) string {
	h.t.Helper()

	query, err := saml.EncodeRedirect([]byte(xmlDoc), relayState, key)
	require.NoError(h.t, err)

	return h.base + "/request?" + query
}

// requestXML is an AuthnRequest of the service provider with the given ID,
// extra attributes on the root element and content after the Issuer.
func (h *harness) requestXML(id, attributes, body string) string {
	return h.requestXMLAt(id, time.Now(), attributes, body)
}

func (h *harness) requestXMLAt(id string, instant time.Time, attributes, body string) string {
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"` +
		` xmlns:req-attr="urn:oasis:names:tc:SAML:protocol:ext:req-attr"` +
		` xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
		` ID="` + id + `" Version="2.0" IssueInstant="` + instant.UTC().Format(time.RFC3339) + `"` +
		` AssertionConsumerServiceURL="` + spACS + `" ` + attributes + `>` +
		`<saml:Issuer>` + spEntityID + `</saml:Issuer>` + body + `</samlp:AuthnRequest>`
}

// --- the browser ---

// page is what /request answered.
type page struct {
	status int
	header http.Header
	body   string
	vars   map[string]any
}

var windowVar = regexp.MustCompile(`window\.([A-Z_]+) = (.*);`)

func (h *harness) get(target string, headers ...string) page {
	h.t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(h.t, err)

	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Do(req)
	require.NoError(h.t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	p := page{status: resp.StatusCode, header: resp.Header, body: string(body), vars: map[string]any{}}

	for _, m := range windowVar.FindAllStringSubmatch(p.body, -1) {
		var value any
		require.NoError(h.t, json.Unmarshal([]byte(m[2]), &value), "window.%s = %s", m[1], m[2])

		p.vars[m[1]] = value
	}

	return p
}

func (p page) str(name string) string {
	s, _ := p.vars[name].(string)

	return s
}

// sessionToken is the IRMA session token in the page's SESSION_DATA.
func (p page) sessionToken(t *testing.T) string {
	t.Helper()

	var data struct {
		Token string `json:"token"`
	}

	require.NoError(t, json.Unmarshal([]byte(p.str("SESSION_DATA")), &data))
	require.NotEmpty(t, data.Token)

	return data.Token
}

// answer is what a POST to the bridge answered.
type answer struct {
	status      int
	contentType string
	body        string
	instruction redirectInstruction
	xml         string
}

func (h *harness) post(path string, body any) answer {
	h.t.Helper()

	var reader io.Reader

	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		require.NoError(h.t, err)

		reader = bytes.NewReader(data)
	}

	resp, err := http.Post(h.base+path, "application/json", reader) //nolint:noctx // a test
	require.NoError(h.t, err)

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	a := answer{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: string(data)}

	if resp.StatusCode == http.StatusOK && strings.HasPrefix(a.contentType, "application/json") {
		require.NoError(h.t, json.Unmarshal(data, &a.instruction))

		if decoded, err := base64.StdEncoding.DecodeString(a.instruction.SAMLResponse); err == nil {
			a.xml = string(decoded)
		} else {
			// The /test endpoints answer with the XML itself.
			a.xml = a.instruction.SAMLResponse
		}
	}

	return a
}

// assert posts the session result and the page's parameters to /assert, as
// the page does once the user has disclosed.
func (h *harness) assert(p page, result string) answer {
	h.t.Helper()

	return h.post("/assert", map[string]string{"token": result, "parameters": p.str("ASSERT_PARAMETERS")})
}

// login runs a complete, successful login and returns the page and the
// answer of /assert.
func (h *harness) login(relayState string, attributes map[string]string) (authnRequest, page, answer) {
	h.t.Helper()

	req := h.redirect(relayState)
	p := h.get(req.url)
	require.Equal(h.t, http.StatusOK, p.status, p.body)

	a := h.assert(p, h.irma.result(p.sessionToken(h.t), attributes))
	require.Equal(h.t, http.StatusOK, a.status, a.body)

	return req, p, a
}

// --- the IRMA server ---

type fakeIrma struct {
	t    *testing.T
	host string
	key  *rsa.PrivateKey

	mu       sync.Mutex
	requests []irmaRequest
	next     int

	// respond, when set, answers instead of starting a session.
	respond http.HandlerFunc
}

// irmaRequest is a session request the bridge sent.
type irmaRequest struct {
	path        string
	contentType string
	claims      map[string]any
	token       string
}

func newFakeIrma(t *testing.T, key *rsa.PrivateKey, requestorKey *rsa.PublicKey) *fakeIrma {
	t.Helper()

	f := &fakeIrma{t: t, key: key}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		// Like the real server, only take a request signed by the
		// requestor it knows.
		claims, err := token.Verify(string(body), requestorKey, time.Now)
		if err != nil {
			http.Error(w, `{"error":"INVALID_REQUEST"}`, http.StatusBadRequest)

			return
		}

		f.mu.Lock()
		f.next++
		sessionToken := "requestor-token-" + string(rune('a'+f.next))
		f.requests = append(f.requests, irmaRequest{
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			claims:      claims,
			token:       sessionToken,
		})
		respond := f.respond
		f.mu.Unlock()

		if respond != nil {
			respond(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      sessionToken,
			"sessionPtr": map[string]string{"u": "http://internal/irma/session/client-token", "irmaqr": "disclosing"},
			"frontendRequest": map[string]string{
				"authorization": "frontend-token", "minProtocolVersion": "1.0", "maxProtocolVersion": "1.1",
			},
		})
	}))
	t.Cleanup(srv.Close)

	f.host = strings.TrimPrefix(srv.URL, "http://")

	return f
}

func (f *fakeIrma) lastRequest() irmaRequest {
	f.t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	require.NotEmpty(f.t, f.requests, "the IRMA server got no session request")

	return f.requests[len(f.requests)-1]
}

func (f *fakeIrma) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.requests)
}

// disclose is the "disclose" of the last session request.
func (f *fakeIrma) disclose() string {
	f.t.Helper()

	request := f.lastRequest().claims["sprequest"].(map[string]any)["request"].(map[string]any)

	data, err := json.Marshal(request["disclose"])
	require.NoError(f.t, err)

	return string(data)
}

// result signs a session result in which the user disclosed the given
// attributes, each as a conjunction of its own.
func (f *fakeIrma) result(sessionToken string, attributes map[string]string) string {
	f.t.Helper()

	return f.resultWith(sessionToken, attributes, nil)
}

// resultWith is result with claims changed or, with a nil value, removed.
func (f *fakeIrma) resultWith(sessionToken string, attributes map[string]string, change map[string]any) string {
	f.t.Helper()

	return signResult(f.t, f.key, sessionToken, attributes, change)
}

func signResult(t *testing.T, key *rsa.PrivateKey, sessionToken string, attributes map[string]string, change map[string]any) string {
	t.Helper()

	disclosed := [][]map[string]any{}

	for id, value := range attributes {
		disclosed = append(disclosed, []map[string]any{{"id": id, "rawvalue": value, "status": "PRESENT"}})
	}

	claims := map[string]any{
		"token":       sessionToken,
		"status":      "DONE",
		"type":        "disclosing",
		"proofStatus": "VALID",
		"disclosed":   disclosed,
		"exp":         time.Now().Add(resultValiditySeconds * time.Second).Unix(),
	}

	for name, value := range change {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}

	signed, err := token.SignClaims(key, "irmaserver", "disclosing_result", claims, time.Now())
	require.NoError(t, err)

	return signed
}

func queryOf(t *testing.T, target string) url.Values {
	t.Helper()

	parsed, err := url.Parse(target)
	require.NoError(t, err)

	return parsed.Query()
}
