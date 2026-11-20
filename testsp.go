package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

// The /test endpoints play the service provider, so that the bridge can be
// tried without a broker. They are part of the Java service and are served
// in every environment; they only work for whoever puts /test/metadata in
// the metadata directory, since the bridge refuses requests of a service
// provider it has no metadata for.

const (
	modeAttributes         = "attributes"
	modeCondiscon          = "condiscon"
	modeCondisconSignicat  = "condiscon-signicat"
	modeCondisconNameID    = "condiscon-nameid"
	modeCondisconAttribute = "condiscon-attribute"

	signicatCondisconName = "signicat:param:condiscon"

	fakeIssuer = "i-am-fake-issuer"

	msgAttributesMode = `When using 'attributes' mode, please provide a list with attributes, i.e. ["attribute"].`
	msgTestReturn     = "This is a placeholder page to which you have been redirected. No SAML response was verified. It is fine to see this page when testing."

	// The fixed login /test/assert and /test/errorassert make a Response for.
	testSPName      = "test"
	testRequestID   = "0"
	testServiceURL  = "http://test"
	testIssuer      = "sidn-irma-saml-bridge"
	testRelayState  = "relay_state_test"
	testAttribute   = "pbdf.gemeente.personalData.fullname"
	testValue       = "W.Geraedts"
	testSessionID   = "0"
	testIrmaIssuer  = "irmaserver"
	testIrmaSubject = "disclosing_result"
)

func (s *server) handleTestMetadata(w http.ResponseWriter, _ *http.Request) {
	data, err := s.idp.TestSPMetadata(s.cfg.constructURL("/test/return"), s.cfg.constructURL("/test/metadata"))
	if err != nil {
		slog.Error("Failed to write metadata", "error", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set(headerContentType, contentTypeMetadata)
	_, _ = w.Write(data)
}

// handleTestRequest makes a signed AuthnRequest and redirects the browser to
// /request with it. "mode" and "request" choose one of the request forms;
// "fake-issuer" and "old-request" make a request that must be refused.
func (s *server) handleTestRequest(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	test := saml.TestRequest{Issuer: s.cfg.issuerName(), IssueInstant: s.now()}

	if query.Has("fake-issuer") {
		test.Issuer = fakeIssuer
	}

	if query.Has("old-request") {
		test.IssueInstant = test.IssueInstant.Add(-24 * time.Hour)
	}

	mode := modeAttributes
	if query.Has("mode") {
		mode = query.Get("mode")
	}

	if query.Has("request") {
		packed := query.Get("request")

		switch mode {
		case modeAttributes:
			if err := json.Unmarshal([]byte(packed), &test.Attributes); err != nil {
				writeText(w, http.StatusBadRequest, msgAttributesMode)

				return
			}

			if len(test.Attributes) == 0 {
				writeText(w, http.StatusUnauthorized, msgAttributesMode)

				return
			}
		case modeCondiscon:
			test.CondisconName, test.Condiscon = modeCondiscon, packed
		case modeCondisconSignicat:
			test.CondisconName, test.Condiscon = signicatCondisconName, packed
		case modeCondisconNameID:
			test.NameIDPolicyFormat = packed
		case modeCondisconAttribute:
			test.AttributeCondiscon = packed
		default:
			slog.Warn("Unknown request mode", "action", "requesttestcontroller")
			w.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	xml, err := test.AuthnRequestXML()
	if err != nil {
		slog.Error("cannot build the test request", "action", "requesttestcontroller", "error", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	// The test service provider signs with the key of the identity
	// provider, which is why its metadata carries the same certificate.
	signed, err := saml.EncodeRedirect(xml, nil, s.keys.samlPrivate)
	if err != nil {
		slog.Error("cannot sign the test request", "action", "requesttestcontroller", "error", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, s.cfg.constructURL("/request")+"?"+signed, http.StatusFound)
}

func handleTestReturn(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, msgTestReturn)
}

// testParameters are the assertion parameters of the fixed test login.
func testParameters(reason *requestError) *assertParameters {
	relay := testRelayState
	condiscon, _ := json.Marshal([][][]string{{{testAttribute}}})

	return &assertParameters{
		SPName:       testSPName,
		RequestID:    testRequestID,
		ServiceURL:   testServiceURL,
		Issuer:       testIssuer,
		Condiscon:    string(condiscon),
		RelayState:   &relay,
		RequestError: reason,
		IrmaToken:    testSessionID,
	}
}

// handleTestAssert plays a complete login: it signs a session result with
// the test IRMA key, runs it through the same checks as /assert, and shows
// the Response as XML instead of base64. It needs testIrmaPrivateKeyPath,
// which production does not set.
func (s *server) handleTestAssert(w http.ResponseWriter, _ *http.Request) {
	if s.keys.testIrmaPrivate == nil {
		writeText(w, http.StatusNotFound, msgNoTestIrmaKey)

		return
	}

	paramsJWT, err := s.signParameters(testParameters(nil))
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())

		return
	}

	result, err := token.SignClaims(s.keys.testIrmaPrivate, testIrmaIssuer, testIrmaSubject, map[string]any{
		"token":       testSessionID,
		"status":      "DONE",
		"type":        "disclosing",
		"proofStatus": "VALID",
		"disclosed": [][]map[string]any{{{
			"rawvalue": testValue,
			"id":       testAttribute,
			"status":   "PRESENT",
		}}},
	}, s.now())
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())

		return
	}

	// The fixed request ID would be a replay on the second call, so this
	// one login is not remembered.
	instruction, xml, berr := s.assert(assertRequest{Parameters: paramsJWT, Token: result}, false)
	if berr != nil {
		writeText(w, berr.status, berr.message)

		return
	}

	instruction.SAMLResponse = string(xml)
	writeJSON(w, http.StatusOK, instruction)
}

// handleTestErrorAssert plays a failed login through /errorassert, or
// /errorassert/abort. The body may hold the error to report.
func (s *server) handleTestErrorAssert(endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reason *requestError

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBody))
		if err != nil {
			writeText(w, http.StatusBadRequest, msgBody)

			return
		}

		if len(body) > 0 {
			if err := json.Unmarshal(body, &reason); err != nil {
				writeText(w, http.StatusBadRequest, msgBody)

				return
			}
		}

		paramsJWT, err := s.signParameters(testParameters(reason))
		if err != nil {
			writeText(w, http.StatusInternalServerError, err.Error())

			return
		}

		var override *requestError
		if endpoint == "/abort" {
			override = userCancelled
		}

		instruction, xml, berr := s.errorAssert(assertRequest{Parameters: paramsJWT}, override)
		if berr != nil {
			writeText(w, berr.status, berr.message)

			return
		}

		instruction.SAMLResponse = string(xml)
		writeJSON(w, http.StatusOK, instruction)
	}
}
