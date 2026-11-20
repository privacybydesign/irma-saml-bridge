package main

import (
	"encoding/base64"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

var disclosedEmail = map[string]string{defaultAttribute: "user@example.com"}

// The whole login: the service provider sends a signed AuthnRequest, the
// bridge starts an IRMA session and shows the page, the page posts the
// session result, and the service provider accepts the Response.
func TestLoginFlow(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("relay/state?a=1&b=2")
	p := h.get(req.url, "Accept-Language", "nl-NL,nl;q=0.9,en;q=0.8")

	require.Equal(t, http.StatusOK, p.status, p.body)
	assert.Equal(t, "text/html;charset=UTF-8", p.header.Get("Content-Type"))

	// The request names no ProviderName, so the IRMA server is the default
	// one, for the service provider "test".
	assert.Equal(t, "http://test.irma.example", p.header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "http://test.irma.example/irma", p.vars["IRMA_SERVER"])
	assert.Equal(t, "nl", p.vars["LANGUAGE"])
	assert.Equal(t, "/saml-bridge/assert", p.vars["ASSERT_URL"])
	assert.Equal(t, "/saml-bridge/errorassert", p.vars["ERROR_ASSERT_URL"])
	assert.Equal(t, "/saml-bridge/report", p.vars["ERROR_URL"])
	assert.Nil(t, p.vars["ERROR"])
	assert.Contains(t, p.body, `<link rel="stylesheet" type="text/css" href="assets/app.css">`)
	assert.Contains(t, p.body, `<script type="module" src="assets/app.js"></script>`)

	// The session request that went to the IRMA server.
	sent := h.irma.lastRequest()
	assert.Equal(t, "/irma/session", sent.path)
	assert.Equal(t, "text/plain", sent.contentType)
	assert.Equal(t, testIssuerName, sent.claims["iss"])
	assert.Equal(t, "verification_request", sent.claims["sub"])
	assert.InDelta(t, float64(time.Now().Unix()), sent.claims["iat"], 5)

	sprequest := sent.claims["sprequest"].(map[string]any)
	assert.InDelta(t, 30, sprequest["validity"], 0)
	assert.Equal(t, map[string]any{
		"@context": "https://irma.app/ld/request/disclosure/v2",
		"disclose": []any{[]any{[]any{defaultAttribute}}},
		"host":     "test.irma.example",
	}, sprequest["request"])

	// The page gets the session data as the IRMA server gave it.
	assert.Equal(t, sent.token, p.sessionToken(t))
	assert.Contains(t, p.str("SESSION_DATA"), `"sessionPtr"`)

	// The user discloses; the page posts the result.
	a := h.assert(p, h.irma.result(sent.token, disclosedEmail))
	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.Equal(t, "application/json", a.contentType)

	require.NotNil(t, a.instruction.ServiceURL)
	assert.Equal(t, spACS, *a.instruction.ServiceURL)
	require.NotNil(t, a.instruction.RelayState)
	assert.Equal(t, "relay/state?a=1&b=2", *a.instruction.RelayState)
	assert.JSONEq(t, `{"samlResponse":"`+a.instruction.SAMLResponse+`","serviceUrl":"`+spACS+`","relayState":"relay/state?a=1&b=2"}`, a.body)

	// The service provider accepts it.
	info, err := h.sp.RetrieveAssertionInfo(a.instruction.SAMLResponse)
	require.NoError(t, err)

	assert.True(t, info.ResponseSignatureValidated)
	assert.False(t, info.WarningInfo.InvalidTime)
	assert.False(t, info.WarningInfo.NotInAudience)
	assert.Equal(t, "user@example.com", info.NameID)
	assert.Equal(t, "user@example.com", info.Values.Get(defaultAttribute))
	assert.Len(t, info.Values, 1)

	assert.Contains(t, a.xml, `InResponseTo="`+req.id+`"`)
	assert.Contains(t, a.xml, `Destination="`+spACS+`"`)
	assert.Contains(t, a.xml, `>`+testIssuerName+`</saml2:Issuer>`)

	// The assertion is valid for responseTtlInSec.
	assertion := info.Assertions[0]
	notBefore, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
	require.NoError(t, err)

	notOnOrAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
	require.NoError(t, err)
	assert.Equal(t, 600*time.Second, notOnOrAfter.Sub(notBefore))
	assert.WithinDuration(t, time.Now(), notBefore, 5*time.Second)
}

// A request can ask for attributes in six ways. Each ends up as the same
// kind of session request at the IRMA server.
func TestRequestForms(t *testing.T) {
	const (
		email  = "irma-demo.sidn-pbdf.email.email"
		domain = "irma-demo.sidn-pbdf.email.domain"
		mobile = "irma-demo.sidn-pbdf.mobilenumber.mobilenumber"

		condiscon = `[[["` + email + `"]],[["` + mobile + `"]]]`
	)

	value := func(name string) string {
		return `<md:RequestedAttribute Name="` + name + `"><saml:AttributeValue xsi:type="xs:string">` + condiscon +
			`</saml:AttributeValue></md:RequestedAttribute>`
	}

	tests := map[string]struct {
		attributes string
		body       string
		disclose   string
	}{
		"1 default": {
			body:     ``,
			disclose: `[[["` + defaultAttribute + `"]]]`,
		},
		"2 requested attributes": {
			// One disjunction per credential, with the attributes of the
			// credential together and in order.
			body: `<samlp:Extensions><req-attr:RequestedAttributes>` +
				`<md:RequestedAttribute isRequired="true" Name="` + mobile + `"/>` +
				`<md:RequestedAttribute isRequired="true" Name="` + email + `"/>` +
				`<md:RequestedAttribute isRequired="false" Name="` + domain + `"/>` +
				`</req-attr:RequestedAttributes></samlp:Extensions>`,
			disclose: `[[["` + domain + `","` + email + `"]],[["` + mobile + `"]]]`,
		},
		"3 condiscon extension": {
			body:     `<samlp:Extensions><req-attr:RequestedAttributes>` + value("condiscon") + `</req-attr:RequestedAttributes></samlp:Extensions>`,
			disclose: condiscon,
		},
		"4 signicat condiscon extension": {
			body:     `<samlp:Extensions><req-attr:RequestedAttributes>` + value("signicat:param:condiscon") + `</req-attr:RequestedAttributes></samlp:Extensions>`,
			disclose: condiscon,
		},
		"5 condiscon in name id policy": {
			body:     `<samlp:NameIDPolicy Format="` + strings.ReplaceAll(condiscon, `"`, `&quot;`) + `"/>`,
			disclose: condiscon,
		},
		"6 condiscon attribute": {
			body: `<samlp:Extensions><saml:Attribute Name="condiscon"><saml:AttributeValue xsi:type="xs:string">` + condiscon +
				`</saml:AttributeValue></saml:Attribute></samlp:Extensions>`,
			disclose: condiscon,
		},
		"the sample from the proposal": {
			body: `<samlp:Extensions><req-attr:RequestedAttributes>` + "\n" +
				`<md:RequestedAttribute isRequired="true" Name="` + email + `" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />` + "\n" +
				`<md:RequestedAttribute isRequired="true" Name="` + domain + `" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />` +
				`</req-attr:RequestedAttributes></samlp:Extensions>` +
				`<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`,
			disclose: `[[["` + domain + `","` + email + `"]]]`,
		},
		"an ordinary name id policy is not a condiscon": {
			body:     `<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>`,
			disclose: `[[["` + defaultAttribute + `"]]]`,
		},
		"an untyped condiscon value is not read": {
			body: `<samlp:Extensions><saml:Attribute Name="condiscon"><saml:AttributeValue>` + condiscon +
				`</saml:AttributeValue></saml:Attribute></samlp:Extensions>`,
			disclose: `[[["` + defaultAttribute + `"]]]`,
		},
	}

	h := newHarness(t, harnessOptions{})

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := h.get(h.customRequest(h.requestXML("_"+strings.ReplaceAll(name, " ", "-"), tt.attributes, tt.body), nil))
			require.Equal(t, http.StatusOK, p.status, p.str("ERROR"))
			assert.JSONEq(t, tt.disclose, h.irma.disclose())
		})
	}
}

// What the user disclosed must be what was asked. Here two credentials are
// requested and both are asserted, with the NameID taken from the first
// attribute by identifier.
func TestLoginWithRequestedAttributes(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	const (
		email  = "pbdf.sidn-pbdf.email.email"
		mobile = "pbdf.sidn-pbdf.mobilenumber.mobilenumber"
	)

	relay := "state"
	body := `<samlp:Extensions><req-attr:RequestedAttributes>` +
		`<md:RequestedAttribute Name="` + mobile + `"/><md:RequestedAttribute Name="` + email + `"/>` +
		`</req-attr:RequestedAttributes></samlp:Extensions>`

	p := h.get(h.customRequest(h.requestXML("_two", `ProviderName="Mapped"`, body), &relay))
	require.Equal(t, http.StatusOK, p.status, p.str("ERROR"))

	// ProviderName, in lower case, picks the IRMA server from irmaMapping.
	assert.Equal(t, "http://irma.mapped.example/mapped", p.vars["IRMA_SERVER"])
	assert.Equal(t, "http://irma.mapped.example", p.header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "/mapped/session", h.irma.lastRequest().path)

	token := p.sessionToken(t)

	// Only one of the two: not what was asked.
	a := h.assert(p, h.irma.result(token, map[string]string{email: "user@example.com"}))
	assert.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, "The disclosure does not match the requested condiscon", a.body)

	a = h.assert(p, h.irma.result(token, map[string]string{email: "user@example.com", mobile: "+31612345678"}))
	require.Equal(t, http.StatusOK, a.status, a.body)

	info, err := h.sp.RetrieveAssertionInfo(a.instruction.SAMLResponse)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", info.NameID)
	assert.Equal(t, "user@example.com", info.Values.Get(email))
	assert.Equal(t, "+31612345678", info.Values.Get(mobile))
}

// A request that was answered cannot be used again: not for a second
// Response, and not to start over.
func TestAnsweredRequestIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("")

	// Before it is answered the request may be loaded again. A phone
	// reloads the page when the user comes back from the Yivi app.
	first := h.get(req.url)
	require.Equal(t, http.StatusOK, first.status)

	second := h.get(req.url)
	require.Equal(t, http.StatusOK, second.status)
	require.NotEqual(t, first.sessionToken(t), second.sessionToken(t))

	result := h.irma.result(second.sessionToken(t), disclosedEmail)

	a := h.assert(second, result)
	require.Equal(t, http.StatusOK, a.status, a.body)

	// The same post again.
	replayed := h.assert(second, result)
	assert.Equal(t, http.StatusConflict, replayed.status)
	assert.Equal(t, "SAML request was already answered", replayed.body)

	// The session of the first page load, completed afterwards.
	other := h.assert(first, h.irma.result(first.sessionToken(t), disclosedEmail))
	assert.Equal(t, http.StatusConflict, other.status)

	// The request itself, sent again.
	again := h.get(req.url)
	assert.Equal(t, http.StatusBadRequest, again.status)
	assert.Equal(t, "SAML request was already answered", again.vars["ERROR"])
	assert.Nil(t, again.vars["SESSION_DATA"])

	// Another request of the same service provider is not affected.
	_, _, fresh := h.login("", disclosedEmail)
	assert.Equal(t, http.StatusOK, fresh.status)
}

// The same request ID from another service provider is another request.
func TestAnsweredRequestIsPerServiceProvider(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.customRequest(h.requestXML("_shared-id", ``, ``), nil))
	require.Equal(t, http.StatusOK, p.status)
	require.Equal(t, http.StatusOK, h.assert(p, h.irma.result(p.sessionToken(t), disclosedEmail)).status)

	assert.True(t, h.srv.answered.Seen("https://sp.example/metadata\x00_shared-id"))
	assert.False(t, h.srv.answered.Seen("https://other.example/metadata\x00_shared-id"))
}

// A failed login does not use the request up: the user can try again.
func TestFailedLoginDoesNotConsumeTheRequest(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("")
	p := h.get(req.url)

	cancelled := h.post("/errorassert/abort", map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
	require.Equal(t, http.StatusOK, cancelled.status)

	refused := h.assert(p, h.irma.resultWith(p.sessionToken(t), disclosedEmail, map[string]any{"proofStatus": "INVALID"}))
	require.Equal(t, http.StatusUnauthorized, refused.status)

	again := h.get(req.url)
	require.Equal(t, http.StatusOK, again.status)

	a := h.assert(again, h.irma.result(again.sessionToken(t), disclosedEmail))
	assert.Equal(t, http.StatusOK, a.status, a.body)
}

// A request older than requestTtlInSec is refused.
func TestExpiredRequestIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("")
	start := time.Now()

	// gosaml2 writes the IssueInstant in whole seconds, so stay a second
	// away from the edge.
	h.srv.now = func() time.Time { return start.Add(899 * time.Second) }
	assert.Equal(t, http.StatusOK, h.get(req.url).status)

	h.srv.now = func() time.Time { return start.Add(902 * time.Second) }

	p := h.get(req.url)
	assert.Equal(t, http.StatusBadRequest, p.status)
	assert.Equal(t, "SAML request is too old, session timeout", p.vars["ERROR"])
	assert.Nil(t, p.vars["SESSION_DATA"])

	// Nothing was started for it.
	assert.Equal(t, 1, h.irma.requestCount())
}

func TestRequestTTLDefaultsTo360Seconds(t *testing.T) {
	h := newHarness(t, harnessOptions{mutate: func(cfg map[string]any) {
		delete(cfg, "requestTtlInSec")
		delete(cfg, "responseTtlInSec")
	}})

	old := h.customRequest(h.requestXMLAt("_old", time.Now().Add(-361*time.Second), ``, ``), nil)
	assert.Equal(t, http.StatusBadRequest, h.get(old).status)

	recent := h.customRequest(h.requestXMLAt("_recent", time.Now().Add(-350*time.Second), ``, ``), nil)
	p := h.get(recent)
	require.Equal(t, http.StatusOK, p.status)

	a := h.assert(p, h.irma.result(p.sessionToken(t), disclosedEmail))
	require.Equal(t, http.StatusOK, a.status)

	info, err := h.sp.RetrieveAssertionInfo(a.instruction.SAMLResponse)
	require.NoError(t, err)

	notBefore, _ := time.Parse(time.RFC3339, info.Assertions[0].Conditions.NotBefore)
	notOnOrAfter, _ := time.Parse(time.RFC3339, info.Assertions[0].Conditions.NotOnOrAfter)
	assert.Equal(t, 360*time.Second, notOnOrAfter.Sub(notBefore))
}

// A request must be signed with the key in the metadata of the service
// provider that says it sent it.
func TestRequestSignatureIsVerified(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	valid := h.redirect("relay")
	require.Equal(t, http.StatusOK, h.get(valid.url).status)

	query := queryOf(t, valid.url)

	without := func(names ...string) string {
		q := url.Values{}
		maps.Copy(q, query)

		for _, name := range names {
			q.Del(name)
		}

		return h.base + "/request?" + q.Encode()
	}

	with := func(name, value string) string {
		q := url.Values{}
		maps.Copy(q, query)

		q.Set(name, value)

		return h.base + "/request?" + q.Encode()
	}

	attacker := testkeys.Key(t, "attacker")

	tests := map[string]string{
		"signed with another key":  h.signedBy(attacker, h.requestXML("_forged", ``, ``), nil),
		"no signature":             without("Signature"),
		"no signature, no sigalg":  without("Signature", "SigAlg"),
		"no sigalg":                without("SigAlg"),
		"relay state changed":      with("RelayState", "other"),
		"relay state removed":      without("RelayState"),
		"request replaced":         with("SAMLRequest", queryOf(t, h.redirect("relay").url).Get("SAMLRequest")),
		"signature of other query": with("Signature", queryOf(t, h.redirect("relay").url).Get("Signature")),
		"algorithm changed":        with("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
		"signature is empty":       with("Signature", ""),
		"signature is zeroes":      with("Signature", base64.StdEncoding.EncodeToString(make([]byte, 256))),
	}

	before := h.irma.requestCount()

	for name, target := range tests {
		t.Run(name, func(t *testing.T) {
			p := h.get(target)
			assert.Equal(t, http.StatusUnauthorized, p.status)
			assert.Equal(t, "SAML request signature malformed", p.vars["ERROR"])
			assert.Nil(t, p.vars["SESSION_DATA"])
			assert.Nil(t, p.vars["IRMA_SERVER"])
		})
	}

	assert.Equal(t, before, h.irma.requestCount(), "no session is started for a request that is not verified")
}

// A service provider without metadata is refused, however it signs.
func TestUnknownServiceProviderIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	issuer := func(entityID string) string {
		return strings.Replace(h.requestXML("_unknown", ``, ``), `<saml:Issuer>`+spEntityID, `<saml:Issuer>`+entityID, 1)
	}

	tests := map[string]string{
		"unknown entity":         issuer("https://unknown.example/metadata"),
		"the bridge itself":      issuer(testIssuerName),
		"almost the same entity": issuer(spEntityID + "/"),
		"other case":             issuer(strings.ToUpper(spEntityID)),
		"empty issuer":           issuer(""),
		"no issuer":              strings.Replace(h.requestXML("_unknown", ``, ``), `<saml:Issuer>`+spEntityID+`</saml:Issuer>`, ``, 1),
		"issuer in another format": strings.Replace(h.requestXML("_unknown", ``, ``), `<saml:Issuer>`,
			`<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">`, 1),
	}

	for name, xmlDoc := range tests {
		t.Run(name, func(t *testing.T) {
			// Signed with the key of the known service provider: the key
			// is found through the issuer, so it does not help.
			p := h.get(h.customRequest(xmlDoc, nil))
			assert.Equal(t, http.StatusUnauthorized, p.status)
			assert.Equal(t, "SAML request signature malformed", p.vars["ERROR"])
		})
	}

	assert.Zero(t, h.irma.requestCount())
}

// Metadata past its validUntil no longer vouches for a service provider.
func TestServiceProviderWithExpiredMetadataIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("")
	require.Equal(t, http.StatusOK, h.get(req.url).status)

	// gosaml2 gives its metadata a validUntil of seven days.
	h.srv.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }

	fresh := h.customRequest(h.requestXMLAt("_later", h.srv.now(), ``, ``), nil)
	assert.Equal(t, http.StatusUnauthorized, h.get(fresh).status)
}

// The Response only goes to an AssertionConsumerService from the metadata
// of the service provider.
func TestResponseOnlyGoesToRegisteredACS(t *testing.T) {
	const redirectACS = "https://sp.example/acs-redirect"

	h := newHarness(t, harnessOptions{spMetadata: func(generated []byte) []byte {
		// A second endpoint, with the HTTP-Redirect binding.
		return []byte(strings.Replace(string(generated), `</SPSSODescriptor>`,
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`+redirectACS+`" index="2"/></SPSSODescriptor>`, 1))
	}})

	request := func(id, acs string) string {
		xmlDoc := h.requestXML(id, ``, ``)
		if acs == "" {
			return strings.Replace(xmlDoc, ` AssertionConsumerServiceURL="`+spACS+`"`, ``, 1)
		}

		return strings.Replace(xmlDoc, `AssertionConsumerServiceURL="`+spACS+`"`, `AssertionConsumerServiceURL="`+acs+`"`, 1)
	}

	for name, acs := range map[string]string{
		"attacker":        "https://attacker.example.com/steal",
		"other path":      spACS + "/../steal",
		"query added":     spACS + "?next=https://attacker.example.com",
		"trailing slash":  spACS + "/",
		"other scheme":    strings.Replace(spACS, "https://", "http://", 1),
		"host suffix":     "https://sp.example.attacker.example/acs",
		"userinfo":        "https://sp.example@attacker.example/acs",
		"javascript":      "javascript:alert(1)",
		"upper case host": "https://SP.example/acs",
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			p := h.get(h.customRequest(request("_acs", acs), nil))
			assert.Equal(t, http.StatusBadRequest, p.status)
			assert.Equal(t, "Requested AssertionConsumerServiceURL is not registered in SP metadata", p.vars["ERROR"])
		})
	}

	assert.Zero(t, h.irma.requestCount())

	for name, tt := range map[string]struct{ acs, want string }{
		"the post endpoint":     {spACS, spACS},
		"the redirect endpoint": {redirectACS, redirectACS},
		// Without a URL in the request, the endpoint with the
		// HTTP-Redirect binding is the default, as in the Java service.
		"no URL in the request": {"", redirectACS},
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			p := h.get(h.customRequest(request("_ok-"+strings.ReplaceAll(name, " ", "-"), tt.acs), nil))
			require.Equal(t, http.StatusOK, p.status, p.str("ERROR"))

			a := h.assert(p, h.irma.result(p.sessionToken(t), disclosedEmail))
			require.Equal(t, http.StatusOK, a.status, a.body)
			require.NotNil(t, a.instruction.ServiceURL)

			assert.Equal(t, tt.want, *a.instruction.ServiceURL)
			assert.Contains(t, a.xml, `Destination="`+tt.want+`"`)
			assert.Contains(t, a.xml, `Recipient="`+tt.want+`"`)
			assert.Equal(t, 1, strings.Count(a.xml, "Destination="))
		})
	}
}

// A service provider that only lists an HTTP-POST endpoint, as the brokers
// do, must name it in the request.
func TestRequestWithoutACSNeedsRedirectEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	xmlDoc := strings.Replace(h.requestXML("_no-acs", ``, ``), ` AssertionConsumerServiceURL="`+spACS+`"`, ``, 1)

	p := h.get(h.customRequest(xmlDoc, nil))
	assert.Equal(t, http.StatusBadRequest, p.status)
	assert.Equal(t, "Return URL is empty (AssertionConsumerServiceURL in SAML)", p.vars["ERROR"])
}

// The service URL in the Response comes from the signed parameters, which
// hold what /request checked. The page cannot change it.
func TestServiceURLCannotBeChangedByThePage(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.redirect("").url)
	result := h.irma.result(p.sessionToken(t), disclosedEmail)

	a := h.post("/assert", map[string]any{
		"token":       result,
		"parameters":  p.str("ASSERT_PARAMETERS"),
		"serviceUrl":  "https://attacker.example.com/steal",
		"service_url": "https://attacker.example.com/steal",
	})
	require.Equal(t, http.StatusOK, a.status)
	assert.Equal(t, spACS, *a.instruction.ServiceURL)
	assert.NotContains(t, a.xml, "attacker")
}
