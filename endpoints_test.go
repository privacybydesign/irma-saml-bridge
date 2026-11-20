package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
)

// Counterpart of ErrorAssertControllerTest.errorTest and errorAbortTest: a
// failed login is reported to the service provider with a signed Response.
func TestErrorAssert(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	req := h.redirect("relay")
	p := h.get(req.url)

	tests := map[string]struct {
		path    string
		message string
	}{
		"error": {"/errorassert", "Something went wrong in the frontend"},
		"abort": {"/errorassert/abort", "The user cancelled."},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := h.post(tt.path, map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
			require.Equal(t, http.StatusOK, a.status, a.body)
			assert.Equal(t, "application/json", a.contentType)

			require.NotNil(t, a.instruction.ServiceURL)
			assert.Equal(t, spACS, *a.instruction.ServiceURL)
			require.NotNil(t, a.instruction.RelayState)
			assert.Equal(t, "relay", *a.instruction.RelayState)

			assert.Contains(t, a.xml, `InResponseTo="`+req.id+`"`)
			assert.Contains(t, a.xml, `Destination="`+spACS+`"`)
			assert.Contains(t, a.xml, `<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">`+
				`<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></saml2p:StatusCode>`+
				`<saml2p:StatusMessage>`+tt.message+`</saml2p:StatusMessage>`)
			assert.NotContains(t, a.xml, "Assertion")

			// Signed like any other Response, and not a login.
			require.NoError(t, h.srv.idp.Verify([]byte(a.xml)))

			_, err := h.sp.RetrieveAssertionInfo(a.instruction.SAMLResponse)
			require.Error(t, err)
		})
	}
}

// When /request cannot read the request there is nobody to answer. The page
// still reports the error; the Response then has no destination.
func TestErrorPage(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.base + "/request")

	assert.Equal(t, http.StatusInternalServerError, p.status)
	assert.Equal(t, "text/html;charset=UTF-8", p.header.Get("Content-Type"))
	assert.Empty(t, p.header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Failed to decode SAML request", p.vars["ERROR"])
	assert.Equal(t, "/saml-bridge/errorassert", p.vars["ERROR_ASSERT_URL"])
	assert.Equal(t, "/saml-bridge/report", p.vars["ERROR_URL"])

	for _, name := range []string{"LANGUAGE", "IRMA_SERVER", "ASSERT_URL", "SESSION_DATA"} {
		value, ok := p.vars[name]
		assert.True(t, ok, name)
		assert.Nil(t, value, name)
	}

	a := h.post("/errorassert", map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
	require.Equal(t, http.StatusOK, a.status, a.body)

	assert.Nil(t, a.instruction.ServiceURL)
	assert.Nil(t, a.instruction.RelayState)
	assert.Contains(t, a.body, `"serviceUrl":null,"relayState":null`)
	assert.Contains(t, a.xml, `<saml2p:StatusMessage>Failed to decode SAML request</saml2p:StatusMessage>`)
	assert.NotContains(t, a.xml, "InResponseTo")
	assert.NotContains(t, a.xml, "Destination")

	// Parameters that only hold an error cannot be turned into a login.
	login := h.post("/assert", map[string]string{
		"parameters": p.str("ASSERT_PARAMETERS"),
		"token":      h.irma.result("any", disclosedEmail),
	})
	assert.NotEqual(t, http.StatusOK, login.status)
}

// The page follows the language the browser prefers: English when that
// comes first, Dutch in every other case.
func TestPageLanguage(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	tests := map[string]struct {
		header string
		want   string
	}{
		"no header":              {"", "nl"},
		"dutch":                  {"nl", "nl"},
		"dutch first":            {"nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7", "nl"},
		"english":                {"en", "en"},
		"british english":        {"en-GB,en;q=0.9", "en"},
		"english first":          {"en-US,en;q=0.9,nl;q=0.8", "en"},
		"english preferred last": {"nl;q=0.5, en;q=0.9", "en"},
		"german":                 {"de-DE,de;q=0.9", "nl"},
		"german then english":    {"de,en;q=0.8", "nl"},
		"wildcard":               {"*", "nl"},
		"english refused":        {"en;q=0, nl", "nl"},
		"garbage":                {";;;,q=,=", "nl"},
		"upper case":             {"EN-us", "en"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, pageLanguage(tt.header))

			var headers []string
			if tt.header != "" {
				headers = []string{"Accept-Language", tt.header}
			}

			p := h.get(h.redirect("").url, headers...)
			require.Equal(t, http.StatusOK, p.status)
			assert.Equal(t, tt.want, p.vars["LANGUAGE"])
			assert.Equal(t, tt.want, p.header.Get("Content-Language"))
		})
	}
}

// When the IRMA server does not start a session the page shows the error,
// with the status the Java service gave.
func TestIrmaServerFailure(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	tests := map[string]struct {
		respond http.HandlerFunc
		status  int
		message string
	}{
		"refused": {
			func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"status":400,"error":"INVALID_REQUEST"}`, http.StatusBadRequest)
			},
			http.StatusBadRequest, "400 Bad Request: \"{\"status\":400,\"error\":\"INVALID_REQUEST\"}<LF>\"",
		},
		"forbidden without body": {
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
			http.StatusForbidden, "403 Forbidden: [no body]",
		},
		"server error": {
			func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
			http.StatusInternalServerError, "Something went wrong when trying to connect with the IRMA server",
		},
		"redirect": {
			func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
			http.StatusInternalServerError, "Start session was not successful",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h.irma.respond = tt.respond

			p := h.get(h.redirect("relay").url)
			assert.Equal(t, tt.status, p.status)
			assert.Equal(t, tt.message, p.vars["ERROR"])
			assert.Nil(t, p.vars["SESSION_DATA"])

			// The service provider hears about it, in the StatusMessage.
			a := h.post("/errorassert", map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
			require.Equal(t, http.StatusOK, a.status)
			assert.Contains(t, a.xml, "<saml2p:StatusMessage>")
			require.NoError(t, h.srv.idp.Verify([]byte(a.xml)))
		})
	}

	t.Run("session data without content", func(t *testing.T) {
		h.irma.respond = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

		p := h.get(h.redirect("").url)
		assert.Equal(t, http.StatusOK, p.status)
		assert.Nil(t, p.vars["SESSION_DATA"])
	})
}

func TestIrmaServerUnreachable(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	h := newHarness(t, harnessOptions{mutate: func(cfg map[string]any) {
		cfg["defaultMap"].(map[string]any)["irmaServiceHost"] = strings.TrimPrefix(closed.URL, "http://")
	}})

	p := h.get(h.redirect("").url)
	assert.Equal(t, http.StatusInternalServerError, p.status)
	assert.Equal(t, "Something went wrong when trying to connect with the IRMA server", p.vars["ERROR"])
}

// The condiscon of a request is refused with the messages of the Java
// service.
func TestCondisconErrors(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	const condiscon = `[[["a.b.c.d"]]]`

	requested := func(inner string) string {
		return `<samlp:Extensions><req-attr:RequestedAttributes>` + inner + `</req-attr:RequestedAttributes></samlp:Extensions>`
	}

	value := func(text string) string {
		return `<saml:AttributeValue xsi:type="xs:string">` + text + `</saml:AttributeValue>`
	}

	tests := map[string]struct {
		body    string
		message string
	}{
		"same attribute twice": {
			requested(`<md:RequestedAttribute Name="a.b.c.d"/><md:RequestedAttribute Name="a.b.c.d"/>`),
			"Cannot request the same irma attribute identifier multiple times",
		},
		"attribute identifier outside the extension": {
			`<samlp:Extensions><saml:Attribute Name="a.b.c.d"/></samlp:Extensions>`,
			"Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension",
		},
		"two condiscons": {
			requested(`<md:RequestedAttribute Name="condiscon">` + value(condiscon) + value(condiscon) + `</md:RequestedAttribute>`),
			"Cannot request for multiple condiscons",
		},
		"two condiscon attributes": {
			requested(`<md:RequestedAttribute Name="condiscon">` + value(condiscon) + `</md:RequestedAttribute>` +
				`<md:RequestedAttribute Name="signicat:param:condiscon">` + value(condiscon) + `</md:RequestedAttribute>`),
			"Cannot request for multiple condiscons",
		},
		"unknown attribute name": {
			requested(`<md:RequestedAttribute Name="email"/>`),
			"Requested XML attribute name is invalid",
		},
		"attribute without a name": {
			requested(`<md:RequestedAttribute/>`),
			"Requested XML attribute name is invalid",
		},
		"condiscon and attributes": {
			requested(`<md:RequestedAttribute Name="a.b.c.d"/><md:RequestedAttribute Name="condiscon">` + value(condiscon) + `</md:RequestedAttribute>`),
			"Cannot mix the condiscon and the requested attributes extension",
		},
		"condiscon is not JSON": {
			requested(`<md:RequestedAttribute Name="condiscon">` + value("not json") + `</md:RequestedAttribute>`),
			"Requested condiscon could not be parsed",
		},
		"condiscon has the wrong shape": {
			requested(`<md:RequestedAttribute Name="condiscon">` + value(`["a.b.c.d"]`) + `</md:RequestedAttribute>`),
			"Requested condiscon could not be parsed",
		},
		"condiscon is null": {
			requested(`<md:RequestedAttribute Name="condiscon">` + value(`null`) + `</md:RequestedAttribute>`),
			"Requested condiscon could not be parsed",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := h.get(h.customRequest(h.requestXML("_condiscon", ``, tt.body), nil))
			assert.Equal(t, http.StatusBadRequest, p.status)
			assert.Equal(t, tt.message, p.vars["ERROR"])
		})
	}

	assert.Zero(t, h.irma.requestCount())
}

func TestIsAttributeIdentifier(t *testing.T) {
	for name, want := range map[string]bool{
		"pbdf.sidn-pbdf.email.email": true,
		"a.b.c.d":                    true,
		"a.b.c.d.":                   true, // as Java's split, which drops empty parts at the end
		".a.b.c":                     true,
		"a.b.c":                      false,
		"a.b.c.d.e":                  false,
		"a.b.c..":                    false,
		"condiscon":                  false,
		"":                           false,
		"...":                        false,
	} {
		assert.Equal(t, want, isAttributeIdentifier(name), name)
	}
}

// --- the built-in test service provider ---

func TestTestRequestEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{registerTestSP: true})

	const (
		attributes = `["irma-demo.sidn-pbdf.email.email","irma-demo.sidn-pbdf.mobilenumber.mobilenumber"]`
		condiscon  = `[[["irma-demo.sidn-pbdf.email.email"]],[["irma-demo.sidn-pbdf.mobilenumber.mobilenumber"]]]`
	)

	// The six request forms of the README.
	forms := map[string]struct {
		query    string
		disclose string
	}{
		"default":             {"", `[[["` + defaultAttribute + `"]]]`},
		"attributes":          {"?mode=attributes&request=" + url.QueryEscape(attributes), condiscon},
		"attributes implied":  {"?request=" + url.QueryEscape(attributes), condiscon},
		"condiscon":           {"?mode=condiscon&request=" + url.QueryEscape(condiscon), condiscon},
		"condiscon-signicat":  {"?mode=condiscon-signicat&request=" + url.QueryEscape(condiscon), condiscon},
		"condiscon-nameid":    {"?mode=condiscon-nameid&request=" + url.QueryEscape(condiscon), condiscon},
		"condiscon-attribute": {"?mode=condiscon-attribute&request=" + url.QueryEscape(condiscon), condiscon},
		"unescaped brackets":  {"?mode=condiscon&request=" + condiscon, condiscon},
	}

	for name, tt := range forms {
		t.Run(name, func(t *testing.T) {
			redirect := h.get(h.base + "/test/request" + tt.query)
			require.Equal(t, http.StatusFound, redirect.status, redirect.body)
			assert.Equal(t, "no-cache, no-store", redirect.header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", redirect.header.Get("Pragma"))

			location := redirect.header.Get("Location")
			require.True(t, strings.HasPrefix(location, h.base+"/request?SAMLRequest="), location)
			assert.Contains(t, location, "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=")

			p := h.get(location)
			require.Equal(t, http.StatusOK, p.status, p.str("ERROR"))
			assert.JSONEq(t, tt.disclose, h.irma.disclose())

			// The Response would go to the test service provider's own
			// endpoint, taken from its metadata.
			a := h.post("/errorassert", map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
			require.Equal(t, http.StatusOK, a.status)
			assert.Equal(t, h.base+"/test/return", *a.instruction.ServiceURL)
		})
	}

	t.Run("fake issuer", func(t *testing.T) {
		p := h.get(h.get(h.base + "/test/request?fake-issuer").header.Get("Location"))
		assert.Equal(t, http.StatusUnauthorized, p.status)
		assert.Equal(t, "SAML request signature malformed", p.vars["ERROR"])
	})

	t.Run("old request", func(t *testing.T) {
		p := h.get(h.get(h.base + "/test/request?old-request=1").header.Get("Location"))
		assert.Equal(t, http.StatusBadRequest, p.status)
		assert.Equal(t, "SAML request is too old, session timeout", p.vars["ERROR"])
	})

	t.Run("empty attribute list", func(t *testing.T) {
		p := h.get(h.base + "/test/request?mode=attributes&request=%5B%5D")
		assert.Equal(t, http.StatusUnauthorized, p.status)
		assert.Equal(t, `When using 'attributes' mode, please provide a list with attributes, i.e. ["attribute"].`, p.body)
	})

	t.Run("attributes not a list", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, h.get(h.base+"/test/request?mode=attributes&request=nope").status)
	})

	t.Run("unknown mode", func(t *testing.T) {
		p := h.get(h.base + "/test/request?mode=zzz&request=%5B%5D")
		assert.Equal(t, http.StatusBadRequest, p.status)
		assert.Empty(t, p.body)
	})
}

// Without its metadata in the metadata directory the test service provider
// is a stranger, like any other.
func TestTestRequestNeedsRegisteredMetadata(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.get(h.base + "/test/request").header.Get("Location"))
	assert.Equal(t, http.StatusUnauthorized, p.status)
}

func TestTestMetadataEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.base + "/test/metadata")
	require.Equal(t, http.StatusOK, p.status)
	assert.Equal(t, "application/samlmetadata+xml", p.header.Get("Content-Type"))

	// It is metadata the bridge itself reads: saving it in the metadata
	// directory is how the test service provider is registered.
	sps, err := saml.ParseMetadata([]byte(p.body))
	require.NoError(t, err)
	require.Len(t, sps, 1)
	assert.Equal(t, testIssuerName, sps[0].EntityID)
	assert.Equal(t, h.base+"/test/return", sps[0].RedirectACS())
	assert.Contains(t, p.body, `<md:OrganizationURL xml:lang="en">`+h.base+`/test/metadata</md:OrganizationURL>`)
}

func TestTestReturnEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	a := h.post("/test/return", "SAMLResponse=x")
	assert.Equal(t, http.StatusOK, a.status)
	assert.Equal(t, "This is a placeholder page to which you have been redirected. No SAML response was verified. It is fine to see this page when testing.", a.body)

	assert.Equal(t, http.StatusMethodNotAllowed, h.get(h.base+"/test/return").status)
}

func TestTestAssertEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for range 2 {
		// The fixed login can be played again and again.
		p := h.get(h.base + "/test/assert")
		require.Equal(t, http.StatusOK, p.status, p.body)
		assert.Equal(t, "application/json", p.header.Get("Content-Type"))

		var instruction redirectInstruction
		require.NoError(t, json.Unmarshal([]byte(p.body), &instruction))

		assert.Equal(t, "http://test", *instruction.ServiceURL)
		assert.Equal(t, "relay_state_test", *instruction.RelayState)

		// The Response is shown as XML, not base64.
		xmlDoc := instruction.SAMLResponse
		require.True(t, strings.HasPrefix(xmlDoc, `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response `), xmlDoc)

		for _, want := range []string{
			`InResponseTo="0"`,
			`Destination="http://test"`,
			`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30"`,
			`<saml2:Audience>sidn-irma-saml-bridge</saml2:Audience>`,
			`<saml2:Attribute Name="pbdf.gemeente.personalData.fullname">`,
			`>W.Geraedts</saml2:NameID>`,
		} {
			assert.Contains(t, xmlDoc, want)
		}

		require.NoError(t, h.srv.idp.Verify([]byte(xmlDoc)))
	}
}

// In production testIrmaPrivateKeyPath is not set, and the endpoint that
// plays the IRMA server has nothing to sign with.
func TestTestAssertNeedsTestIrmaKey(t *testing.T) {
	h := newHarness(t, harnessOptions{mutate: func(cfg map[string]any) {
		cfg["testIrmaPrivateKeyPath"] = nil
	}})

	p := h.get(h.base + "/test/assert")
	assert.Equal(t, http.StatusNotFound, p.status)
	assert.Equal(t, "testIrmaPrivateKeyPath is not configured", p.body)
	assert.NotContains(t, p.body, "saml2p:Response")
}

func TestTestErrorAssertEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	tests := map[string]struct {
		path    string
		body    any
		message string
	}{
		"default":       {"/test/errorassert", nil, "Something went wrong in the frontend"},
		"given error":   {"/test/errorassert", `{"statusCode":418,"message":"custom <error>"}`, "custom &lt;error&gt;"},
		"abort":         {"/test/errorassert/abort", nil, "The user cancelled."},
		"abort decides": {"/test/errorassert/abort", `{"statusCode":418,"message":"ignored"}`, "The user cancelled."},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := h.post(tt.path, tt.body)
			require.Equal(t, http.StatusOK, a.status, a.body)
			assert.Equal(t, "http://test", *a.instruction.ServiceURL)
			assert.Equal(t, "relay_state_test", *a.instruction.RelayState)
			assert.Contains(t, a.xml, `<saml2p:StatusMessage>`+tt.message+`</saml2p:StatusMessage>`)
			assert.Contains(t, a.xml, `InResponseTo="0"`)
			require.NoError(t, h.srv.idp.Verify([]byte(a.xml)))
		})
	}

	assert.Equal(t, http.StatusBadRequest, h.post("/test/errorassert", "not json").status)
}

// --- probes, context path, metadata, report, assets ---

// The probes of the deployment keep working: Kubernetes asks for
// /actuator/health/liveness and /actuator/health/readiness.
func TestHealthEndpoints(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for path, body := range map[string]string{
		"/actuator/health":           `{"status":"UP","groups":["liveness","readiness"]}`,
		"/actuator/health/liveness":  `{"status":"UP"}`,
		"/actuator/health/readiness": `{"status":"UP"}`,
	} {
		p := h.get(h.base + path)
		assert.Equal(t, http.StatusOK, p.status, path)
		assert.Equal(t, body, p.body, path)
		assert.Equal(t, "application/vnd.spring-boot.actuator.v3+json", p.header.Get("Content-Type"), path)
	}
}

func TestContextPath(t *testing.T) {
	paths := []string{"/actuator/health/liveness", "/actuator/health/readiness", "/metadata", "/test/metadata"}

	t.Run("from the environment", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		root := strings.TrimSuffix(h.base, testContextPath)

		for _, path := range paths {
			assert.Equal(t, http.StatusOK, h.get(root+"/saml-bridge"+path).status, path)
			assert.Equal(t, http.StatusNotFound, h.get(root+"/irma-saml-bridge"+path).status, path)
			assert.Equal(t, http.StatusNotFound, h.get(root+path).status, path)
		}

		for _, path := range []string{"", "/", "/saml-bridge", "/saml-bridge/", "/saml-bridge/request/", "/saml-bridge/nope", "/saml-bridge/actuator", "/saml-bridge/actuator/info", "/saml-bridge/actuator/prometheus", "/saml-bridge/up"} {
			assert.Equal(t, http.StatusNotFound, h.get(root+path).status, path)
		}
	})

	t.Run("default", func(t *testing.T) {
		unset := ""
		h := newHarness(t, harnessOptions{contextPath: &unset})
		root := strings.TrimSuffix(h.base, defaultContextPath)

		for _, path := range paths {
			assert.Equal(t, http.StatusOK, h.get(root+"/irma-saml-bridge"+path).status, path)
			assert.Equal(t, http.StatusNotFound, h.get(root+"/saml-bridge"+path).status, path)
		}
	})
}

func TestMethodNotAllowed(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for _, path := range []string{"/assert", "/errorassert", "/errorassert/abort", "/report", "/test/return", "/test/errorassert"} {
		p := h.get(h.base + path)
		assert.Equal(t, http.StatusMethodNotAllowed, p.status, path)
		assert.Equal(t, "POST", p.header.Get("Allow"), path)
	}

	for _, path := range []string{"/request", "/metadata", "/test/request", "/test/assert", "/actuator/health"} {
		a := h.post(path, "{}")
		assert.Equal(t, http.StatusMethodNotAllowed, a.status, path)
	}
}

// Counterpart of MetadataControllerTest.metadataTest.
func TestMetadataEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	p := h.get(h.base + "/metadata")
	require.Equal(t, http.StatusOK, p.status)
	assert.Equal(t, "application/samlmetadata+xml", p.header.Get("Content-Type"))

	assert.True(t, strings.HasPrefix(p.body, `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="P0Y0M0DT0H0M30.000S" entityID="`+testIssuerName+`">`), p.body)
	assert.Contains(t, p.body, `<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	assert.Contains(t, p.body, `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`+h.base+`/request"/>`)
	assert.Contains(t, p.body, `<md:KeyDescriptor use="signing">`)

	// The certificate in the metadata is the one Responses are signed with.
	_, _, a := h.login("", disclosedEmail)
	certificate := p.body[strings.Index(p.body, "<ds:X509Certificate>"):strings.Index(p.body, "</ds:X509Certificate>")]
	assert.Contains(t, a.xml, certificate)
}

// Counterpart of MetadataControllerTest.metadataTestThrowCertificateEncodingException.
func TestMetadataEndpointFailure(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.srv.metadata = func() ([]byte, error) { return nil, errors.New("cannot encode") }

	p := h.get(h.base + "/metadata")
	assert.Equal(t, http.StatusInternalServerError, p.status)
	assert.NotContains(t, p.body, "EntityDescriptor")
}

func TestReportEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for name, body := range map[string]string{
		"error":               `{"message":"Uncaught TypeError","source":"https://bridge.example/assets/app.js","lineno":12,"colno":34}`,
		"unhandled rejection": `{"isTrusted":true}`,
		"numbers as strings":  `{"message":"m","lineno":"12","colno":"34"}`,
		"long and multi-line": `{"message":"` + strings.Repeat(`a\n`, 1000) + `","source":"` + strings.Repeat("s", 500) + `"}`,
		"empty object":        `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			a := h.post("/report", body)
			assert.Equal(t, http.StatusOK, a.status)
			assert.Empty(t, a.body)
		})
	}

	assert.Equal(t, http.StatusBadRequest, h.post("/report", "not json").status)

	assert.Equal(t, "abc", limit("abcdef", 3))
	assert.Equal(t, "ab", limit("ab", 3))
	assert.Equal(t, "éé", limit("ééé", 2))
}

// The page's script and style sheet are served next to it. Nothing else in
// the directory is, and nothing outside it.
func TestAssets(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.srv.assets = fstest.MapFS{
		"app.js":       {Data: []byte(`console.log("yivi")`)},
		"app.css":      {Data: []byte(`body{margin:0}`)},
		".gitkeep":     {Data: []byte{}},
		"sub/inner.js": {Data: []byte(`secret`)},
	}

	js := h.get(h.base + "/assets/app.js")
	assert.Equal(t, http.StatusOK, js.status)
	assert.Equal(t, `console.log("yivi")`, js.body)
	assert.Contains(t, js.header.Get("Content-Type"), "javascript")

	css := h.get(h.base + "/assets/app.css")
	assert.Equal(t, http.StatusOK, css.status)
	assert.Contains(t, css.header.Get("Content-Type"), "text/css")

	// The browser may keep its copy as long as the file is the same.
	etag := js.header.Get("ETag")
	require.NotEmpty(t, etag)
	assert.NotEqual(t, etag, css.header.Get("ETag"))
	assert.Equal(t, "no-cache", js.header.Get("Cache-Control"))

	cached := h.get(h.base+"/assets/app.js", "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, cached.status)
	assert.Empty(t, cached.body)

	changed := h.get(h.base+"/assets/app.js", "If-None-Match", `"other"`)
	assert.Equal(t, http.StatusOK, changed.status)

	for _, path := range []string{"/assets/", "/assets", "/assets/.gitkeep", "/assets/missing.js", "/assets/sub/inner.js", "/assets/sub", "/assets/..%2Fgo.mod", "/assets/%2e%2e/go.mod", "/go.mod", "/config.test.json", "/dev-keys/idp.der"} {
		p := h.get(h.base + path)
		assert.Equal(t, http.StatusNotFound, p.status, path)
		assert.NotContains(t, p.body, "secret", path)
		assert.NotContains(t, p.body, "module github.com", path)
	}

	// The server cleans a path with dots and sends the browser to a path
	// that does not exist.
	dots := h.get(h.base + "/assets/../go.mod")
	require.True(t, dots.status >= 300 && dots.status < 400, "status %d", dots.status)
	assert.Equal(t, testContextPath+"/go.mod", dots.header.Get("Location"))
	assert.Equal(t, http.StatusNotFound, h.get(h.base+"/go.mod").status)
}

// The directory that is embedded exists in the repository, so the service
// builds without the node stage. With the node stage it holds the bundle.
func TestEmbeddedAssetsDirectory(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	entries, err := os.ReadDir("static/assets")
	require.NoError(t, err)

	for _, entry := range entries {
		p := h.get(h.base + "/assets/" + entry.Name())

		if strings.HasPrefix(entry.Name(), ".") {
			assert.Equal(t, http.StatusNotFound, p.status, entry.Name())

			continue
		}

		assert.Equal(t, http.StatusOK, p.status, entry.Name())
	}
}

// --- failures while making the Response ---

// failingResponder fails at one step of making a Response.
type failingResponder struct {
	responder
	step string
}

var errStep = errors.New("failed on purpose")

func (f failingResponder) Sign(r *saml.Response) error {
	if f.step == "sign" {
		return errStep
	}

	return f.responder.Sign(r)
}

func (f failingResponder) Marshal(r *saml.Response) ([]byte, error) {
	if f.step == "marshal" {
		return nil, errStep
	}

	return f.responder.Marshal(r)
}

func (f failingResponder) Verify(data []byte) error {
	if f.step == "verify" {
		return errStep
	}

	return f.responder.Verify(data)
}

// Counterpart of RedirectInstructionServiceTest.createTestExceptions,
// AssertControllerTest.reportTestBridgeException and
// ErrorAssertControllerTest.errorTestWithBridgeException.
func TestResponseFailures(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	real := h.srv.responder

	for step, message := range map[string]string{
		"sign":    "Failed to write signature",
		"marshal": "Failed to write assertion",
		"verify":  "Failed to validate signature or format of our assertion",
	} {
		t.Run(step, func(t *testing.T) {
			h.srv.responder = failingResponder{responder: real, step: step}

			p := h.get(h.redirect("").url)

			a := h.assert(p, h.irma.result(p.sessionToken(t), disclosedEmail))
			assert.Equal(t, http.StatusInternalServerError, a.status)
			assert.Equal(t, message, a.body)

			e := h.post("/errorassert", map[string]string{"parameters": p.str("ASSERT_PARAMETERS")})
			assert.Equal(t, http.StatusInternalServerError, e.status)
			assert.Equal(t, message, e.body)
		})
	}

	// Counterpart of RedirectInstructionServiceTest.createTest.
	h.srv.responder = real

	instruction, xmlDoc, berr := h.srv.redirectInstruction(&assertParameters{ServiceURL: spACS}, saml.ResponseParams{})
	require.Nil(t, berr)
	assert.NotEmpty(t, instruction.SAMLResponse)
	assert.Equal(t, spACS, *instruction.ServiceURL)
	require.NoError(t, h.srv.idp.Verify(xmlDoc))
}

// A Response that does not verify with the bridge's own certificate never
// leaves it.
func TestResponseIsVerifiedBeforeItIsHandedOut(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.srv.responder = tamperingResponder{h.srv.responder}

	p := h.get(h.redirect("").url)

	a := h.assert(p, h.irma.result(p.sessionToken(t), disclosedEmail))
	assert.Equal(t, http.StatusInternalServerError, a.status)
	assert.Equal(t, "Failed to validate signature or format of our assertion", a.body)
}

// tamperingResponder changes the Response after it was signed.
type tamperingResponder struct{ responder }

func (r tamperingResponder) Marshal(response *saml.Response) ([]byte, error) {
	data, err := r.responder.Marshal(response)

	return []byte(strings.Replace(string(data), "user@example.com", "admin@example.com", 1)), err
}

func TestServerTimeoutsAndLimits(t *testing.T) {
	assert.Equal(t, 16<<10, maxHeaderBytes)
	assert.Less(t, readHeaderTimeout, time.Minute)

	// A request line beyond the limit never reaches a handler.
	h := newHarness(t, harnessOptions{})

	srv := httptest.NewUnstartedServer(h.srv.routes())
	srv.Config.MaxHeaderBytes = maxHeaderBytes
	srv.Start()
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + testContextPath + "/request?SAMLRequest=" + strings.Repeat("A", 64<<10)) //nolint:noctx // a test
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, resp.Body)
	assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode)
}
