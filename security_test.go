package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

// The session result must be signed by the IRMA server whose key is in
// irmaPublicKeyPath, be valid, and belong to the session of this request.
func TestSessionResultIsVerified(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.redirect("").url)
	require.Equal(t, http.StatusOK, p.status)

	session := p.sessionToken(t)

	// Another session of the same IRMA server, in which the same
	// attribute was disclosed, for instance by the attacker themself.
	other := h.get(h.redirect("").url).sessionToken(t)

	tests := map[string]struct {
		result string
		status int
		body   string
	}{
		"signed with another key": {
			signResult(t, testkeys.Key(t, "attacker"), session, disclosedEmail, nil),
			http.StatusUnauthorized, "Invalid IRMA session result",
		},
		"signed with the bridge's own key": {
			signResult(t, testkeys.Key(t, "jwt"), session, disclosedEmail, nil),
			http.StatusUnauthorized, "Invalid IRMA session result",
		},
		"expired": {
			h.irma.resultWith(session, disclosedEmail, map[string]any{"exp": time.Now().Add(-time.Second).Unix()}),
			http.StatusUnauthorized, "Invalid IRMA session result",
		},
		"not yet valid": {
			h.irma.resultWith(session, disclosedEmail, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}),
			http.StatusUnauthorized, "Invalid IRMA session result",
		},
		"not a token":               {"not.a.token", http.StatusUnauthorized, "Invalid IRMA session result"},
		"empty":                     {"", http.StatusUnauthorized, "Invalid IRMA session result"},
		"the page's own parameters": {p.str("ASSERT_PARAMETERS"), http.StatusUnauthorized, "Invalid IRMA session result"},
		"proof invalid": {
			h.irma.resultWith(session, disclosedEmail, map[string]any{"proofStatus": "INVALID"}),
			http.StatusUnauthorized, "Expected valid proof and present attributes",
		},
		"no proof status": {
			h.irma.resultWith(session, disclosedEmail, map[string]any{"proofStatus": nil}),
			http.StatusUnauthorized, "Expected valid proof and present attributes",
		},
		"nothing disclosed": {
			h.irma.result(session, nil),
			http.StatusUnauthorized, "Expected valid proof and present attributes",
		},
		"attribute not present": {
			h.irma.resultWith(session, nil, map[string]any{"disclosed": [][]map[string]any{{
				{"id": defaultAttribute, "rawvalue": nil, "status": "NULL"},
			}}}),
			http.StatusUnauthorized, "Expected valid proof and present attributes",
		},
		"another attribute": {
			h.irma.result(session, map[string]string{"irma-demo.sidn-pbdf.email.domain": "example.com"}),
			http.StatusUnauthorized, "The disclosure does not match the requested condiscon",
		},
		"malformed disclosure": {
			h.irma.resultWith(session, nil, map[string]any{"disclosed": "malformedClaim"}),
			http.StatusBadRequest, "Received malformed disclosure",
		},
		"another session": {
			h.irma.result(other, disclosedEmail),
			http.StatusUnauthorized, "The disclosure does not belong to this request",
		},
		"no session token": {
			h.irma.resultWith(session, disclosedEmail, map[string]any{"token": nil}),
			http.StatusUnauthorized, "The disclosure does not belong to this request",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := h.assert(p, tt.result)
			assert.Equal(t, tt.status, a.status)
			assert.Equal(t, tt.body, a.body)
			assert.Empty(t, a.xml)
		})
	}

	// None of that used the request up.
	a := h.assert(p, h.irma.result(session, disclosedEmail))
	assert.Equal(t, http.StatusOK, a.status, a.body)
}

// The parameters are the bridge's own statement about the request. Only a
// token it signed for that purpose is taken.
func TestAssertParametersAreVerified(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.redirect("").url)
	result := h.irma.result(p.sessionToken(t), disclosedEmail)

	claim, err := (&assertParameters{
		SPName:     "test",
		RequestID:  "_forged",
		ServiceURL: "https://attacker.example.com/steal",
		Issuer:     spEntityID,
		Condiscon:  `[[["` + defaultAttribute + `"]]]`,
		IrmaToken:  p.sessionToken(t),
	}).claim()
	require.NoError(t, err)

	forged, err := token.Sign(testkeys.Key(t, "attacker"), testIssuerName, subjectParameters, claimParameters, claim, time.Now())
	require.NoError(t, err)

	// Signed with the right key, but as a session request for the IRMA
	// server: the same key signs those, and the service provider chooses
	// part of their content.
	asSessionRequest, err := token.Sign(testkeys.Key(t, "jwt"), testIssuerName, subjectSessionRequest, claimParameters, claim, time.Now())
	require.NoError(t, err)

	withoutClaim, err := token.Sign(testkeys.Key(t, "jwt"), testIssuerName, subjectParameters, "other", claim, time.Now())
	require.NoError(t, err)

	parts := strings.Split(p.str("ASSERT_PARAMETERS"), ".")
	tampered := parts[0] + "." + strings.Split(forged, ".")[1] + "." + parts[2]

	for name, parameters := range map[string]string{
		"signed with another key":       forged,
		"a session request":             asSessionRequest,
		"no parameters claim":           withoutClaim,
		"payload replaced":              tampered,
		"the session result":            result,
		"the IRMA session request sent": "",
		"not a token":                   "x",
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/assert", "/errorassert", "/errorassert/abort"} {
				a := h.post(path, map[string]string{"token": result, "parameters": parameters})
				assert.Equal(t, http.StatusUnauthorized, a.status, path)
				assert.Equal(t, "Invalid assertion parameters", a.body, path)
			}
		})
	}
}

// XML with a DTD or entities, and input that is too large, is refused at
// the endpoint, signed or not.
func TestRequestEndpointRejectsUnsafeXML(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	valid := h.requestXML("_xml", ``, ``)

	tests := map[string]string{
		"doctype": `<!DOCTYPE samlp:AuthnRequest>` + valid,
		"external entity": `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
			strings.Replace(valid, `<saml:Issuer>`+spEntityID, `<saml:Issuer>&xxe;`, 1),
		"billion laughs": `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>` +
			strings.Replace(valid, `</samlp:AuthnRequest>`, `<x>&lol2;</x></samlp:AuthnRequest>`, 1),
		"undeclared entity": strings.Replace(valid, `</samlp:AuthnRequest>`, `<x>&undeclared;</x></samlp:AuthnRequest>`, 1),
		// 4 MiB of spaces deflates to a few kilobytes.
		"deflate bomb": strings.Replace(valid, `</samlp:AuthnRequest>`, strings.Repeat(" ", 4<<20)+`</samlp:AuthnRequest>`, 1),
		"just over the limit": strings.Replace(valid, `</samlp:AuthnRequest>`,
			strings.Repeat(" ", saml.MaxRequestXMLBytes-len(valid)+1)+`</samlp:AuthnRequest>`, 1),
		"too deep": strings.Replace(valid, `</samlp:AuthnRequest>`, strings.Repeat("<a>", 100)+strings.Repeat("</a>", 100)+`</samlp:AuthnRequest>`, 1),
		"no ID":    strings.Replace(valid, ` ID="_xml"`, ``, 1),
	}

	for name, xmlDoc := range tests {
		t.Run(name, func(t *testing.T) {
			target := h.customRequest(xmlDoc, nil)
			require.Less(t, len(target), maxHeaderBytes, "the request fits in a URL the server reads")

			p := h.get(target)
			assert.Equal(t, http.StatusInternalServerError, p.status)
			assert.Equal(t, "Failed to decode SAML request", p.vars["ERROR"])
			assert.NotContains(t, p.body, "root:")
		})
	}

	// A request of exactly the limit is still read.
	exact := strings.Replace(valid, `</samlp:AuthnRequest>`, strings.Repeat(" ", saml.MaxRequestXMLBytes-len(valid))+`</samlp:AuthnRequest>`, 1)
	require.Len(t, exact, saml.MaxRequestXMLBytes)
	assert.Equal(t, http.StatusOK, h.get(h.customRequest(exact, nil)).status)

	assert.Equal(t, 1, h.irma.requestCount())
}

// A message that is not an AuthnRequest is refused before its signature is
// looked at.
func TestOtherSAMLMessagesAreRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	logout := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="_logout" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"><saml:Issuer>` + spEntityID + `</saml:Issuer></samlp:LogoutRequest>`

	p := h.get(h.customRequest(logout, nil))
	assert.Equal(t, http.StatusBadRequest, p.status)
	assert.Equal(t, "SAML request is not an Authnrequest", p.vars["ERROR"])
}

// A query that repeats a SAML parameter is refused, so that the request
// that is verified is the request that is read.
func TestRepeatedQueryParametersAreRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	valid := h.redirect("").url
	evil := h.signedBy(testkeys.Key(t, "attacker"), h.requestXML("_evil", ``, ``), nil)
	evilRequest := "SAMLRequest=" + strings.SplitN(strings.SplitN(evil, "SAMLRequest=", 2)[1], "&", 2)[0]

	for name, target := range map[string]string{
		"second SAMLRequest": valid + "&" + evilRequest,
		"first SAMLRequest":  strings.Replace(valid, "/request?", "/request?"+evilRequest+"&", 1),
		"second Signature":   valid + "&Signature=AAAA",
		"encoded name":       valid + "&SAML%52equest=AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			p := h.get(target)
			assert.Equal(t, http.StatusInternalServerError, p.status)
			assert.Equal(t, "Failed to decode SAML request", p.vars["ERROR"])
		})
	}
}

// What a request says is escaped on the page. Here the relay state and the
// provider name try to leave the script block.
func TestPageEscapesWhatTheRequestSays(t *testing.T) {
	h := newHarness(t, harnessOptions{mutate: func(cfg map[string]any) {
		cfg["defaultMap"].(map[string]any)["postfix"] = "/{spName}"
	}})

	relay := `</script><script>alert(1)</script>`

	p := h.get(h.customRequest(h.requestXML("_xss", `ProviderName="&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;"`, ``), &relay))
	require.Equal(t, http.StatusOK, p.status, p.str("ERROR"))

	assert.Equal(t, 2, strings.Count(p.body, "</script>"), "only the page's own script elements end")
	assert.NotContains(t, p.body, "<img")
	assert.Equal(t, "http://</script><img src=x onerror=alert(1)>.irma.example/</script><img src=x onerror=alert(1)>", p.vars["IRMA_SERVER"])
}

// The bodies the page posts are bounded.
func TestPostBodiesAreBounded(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	large := `{"parameters":"` + strings.Repeat("a", maxAssertBody) + `"}`

	for _, path := range []string{"/assert", "/errorassert", "/errorassert/abort"} {
		a := h.post(path, large)
		assert.Equal(t, http.StatusBadRequest, a.status, path)
		assert.Equal(t, "Invalid request body", a.body, path)
	}

	a := h.post("/report", `{"message":"`+strings.Repeat("a", maxReportBody)+`"}`)
	assert.Equal(t, http.StatusBadRequest, a.status)

	for _, body := range []string{``, `x`, `[]`, `"string"`, `{"parameters": 5}`} {
		assert.Equal(t, http.StatusBadRequest, h.post("/assert", body).status, body)
		assert.Equal(t, http.StatusBadRequest, h.post("/errorassert", body).status, body)
	}
}
