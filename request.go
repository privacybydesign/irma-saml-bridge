package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/privacybydesign/irma-saml-bridge/internal/irma"
	"github.com/privacybydesign/irma-saml-bridge/internal/replay"
	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

const (
	actionRequest = "request-flow"

	irmaDisclosureContext = "https://irma.app/ld/request/disclosure/v2"

	// resultValiditySeconds is how long the IRMA server's session result
	// JWT is valid.
	resultValiditySeconds = 30

	// defaultSPName is used for a request without a ProviderName.
	defaultSPName = "test"

	langNL = "nl"
	langEN = "en"

	subjectSessionRequest = "verification_request"
	claimSessionRequest   = "sprequest"

	msgDecode       = "Failed to decode SAML request"
	msgNotAuthn     = "SAML request is not an Authnrequest"
	msgSignature    = "SAML request signature malformed"
	msgTooOld       = "SAML request is too old, session timeout"
	msgAnswered     = "SAML request was already answered"
	msgDuplicate    = "Cannot request the same irma attribute identifier multiple times"
	msgNotRequested = "Requesting individual irma attribute identifiers is only supported using the RequestedAttributes extension"
	msgMultiple     = "Cannot request for multiple condiscons"
	msgAttrName     = "Requested XML attribute name is invalid"
	msgMix          = "Cannot mix the condiscon and the requested attributes extension"
	msgCondiscon    = "Requested condiscon could not be parsed"
	msgACS          = "Requested AssertionConsumerServiceURL is not registered in SP metadata"
	msgNoACS        = "Return URL is empty (AssertionConsumerServiceURL in SAML)"
)

// requestError is an error that is shown to the user and, through the
// assertion parameters, ends up as the StatusMessage of the SAML Response.
type requestError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

// pageData fills the page. A nil value is written as null.
type pageData struct {
	Language         any
	IrmaServer       any
	AssertURL        any
	ErrorAssertURL   any
	AssertParameters any
	Error            any
	ErrorURL         any
	SessionData      any
}

// handleRequest takes a signed AuthnRequest in the HTTP-Redirect binding,
// starts an IRMA session for what it asks, and answers with the page that
// shows the QR code.
func (s *server) handleRequest(w http.ResponseWriter, r *http.Request) {
	msg, err := saml.DecodeRedirect(r.URL.RawQuery)
	if err != nil {
		slog.Warn(msgDecode, "action", actionRequest, "error", err)
		s.showError(w, http.StatusInternalServerError, msgDecode)

		return
	}

	req, err := saml.ParseAuthnRequest(msg.XML)
	if errors.Is(err, saml.ErrNotAuthnRequest) {
		slog.Warn(msgNotAuthn, "action", actionRequest, "error", err)
		s.showError(w, http.StatusBadRequest, msgNotAuthn)

		return
	}

	if err != nil {
		slog.Warn(msgDecode, "action", actionRequest, "error", err)
		s.showError(w, http.StatusInternalServerError, msgDecode)

		return
	}

	sp, err := s.authenticate(msg, req)
	if err != nil {
		slog.Warn(msgSignature, "action", actionRequest, "issuer", req.Issuer, "sigalg", msg.SigAlg(), "error", err)
		s.showError(w, http.StatusUnauthorized, msgSignature)

		return
	}

	now := s.now()

	if req.IssueInstant.Before(now.Add(-s.cfg.requestTTL())) {
		slog.Warn(msgTooOld, "action", actionRequest, "issuer", req.Issuer)
		s.showError(w, http.StatusBadRequest, msgTooOld)

		return
	}

	if s.answered.Seen(replay.Key(req.Issuer, req.ID)) {
		slog.Warn(msgAnswered, "action", actionRequest, "issuer", req.Issuer)
		s.showError(w, http.StatusBadRequest, msgAnswered)

		return
	}

	if sso := s.cfg.constructURL("/request"); req.Destination != "" && req.Destination != sso {
		// Not refused: the Java service never looked at the Destination.
		slog.Warn("Destination of the SAML request is not the single sign-on URL",
			"action", actionRequest, "issuer", req.Issuer, "destination", req.Destination, "expected", sso)
	}

	condiscon, rerr := s.condiscon(req)
	if rerr != nil {
		slog.Warn(rerr.Message, "action", actionRequest, "issuer", req.Issuer)
		s.showError(w, rerr.StatusCode, rerr.Message)

		return
	}

	returnURL := req.ACSURL
	if returnURL == "" {
		returnURL = sp.RedirectACS()
	} else if !sp.HasACS(returnURL) {
		slog.Warn(msgACS, "action", actionRequest, "issuer", req.Issuer, "url", returnURL)
		s.showError(w, http.StatusBadRequest, msgACS)

		return
	}

	if returnURL == "" {
		slog.Warn(msgNoACS, "action", actionRequest, "issuer", req.Issuer)
		s.showError(w, http.StatusBadRequest, msgNoACS)

		return
	}

	// ProviderName selects the IRMA server, a convention of the broker.
	spName := defaultSPName
	if req.ProviderName != nil {
		spName = strings.ToLower(*req.ProviderName)
	}

	target := s.cfg.irmaPathFor(spName)

	sessionRequest, err := token.Sign(s.keys.jwtPrivate, s.cfg.issuerName(), subjectSessionRequest, claimSessionRequest,
		map[string]any{
			"request": map[string]any{
				"@context": irmaDisclosureContext,
				"disclose": condiscon,
				"host":     target.Host,
			},
			"validity": resultValiditySeconds,
		}, now)
	if err != nil {
		slog.Error("cannot sign the IRMA session request", "action", actionRequest, "error", err)
		s.showError(w, http.StatusInternalServerError, "Failed to sign the IRMA session request")

		return
	}

	// The session is started here, not by the browser, so that a request
	// the IRMA server refuses fails before the page is shown.
	sessionData, err := s.irma.StartSession(r.Context(), s.cfg.protocol()+target.IrmaServiceHost+target.Postfix, sessionRequest)
	if err != nil {
		var irmaErr *irma.Error
		if !errors.As(err, &irmaErr) {
			irmaErr = &irma.Error{Status: http.StatusInternalServerError, Message: err.Error()}
		}

		s.showError(w, irmaErr.Status, irmaErr.Message)

		return
	}

	repacked, err := json.Marshal(condiscon)
	if err != nil {
		s.showError(w, http.StatusInternalServerError, msgCondiscon)

		return
	}

	params := &assertParameters{
		SPName:       spName,
		RequestID:    req.ID,
		ServiceURL:   returnURL,
		Issuer:       req.Issuer,
		Condiscon:    string(repacked),
		RelayState:   msg.RelayState,
		IrmaToken:    sessionToken(sessionData),
		IssueInstant: req.IssueInstant.Unix(),
	}

	paramsJWT, err := s.signParameters(params)
	if err != nil {
		slog.Error("cannot sign the assertion parameters", "action", actionRequest, "error", err)
		s.showError(w, http.StatusInternalServerError, "Failed to sign the assertion parameters")

		return
	}

	// The browser fetches the session from the IRMA server under the name
	// the user sees, which is another origin than this page.
	external := s.cfg.protocol() + target.Host
	language := pageLanguage(r.Header.Get("Accept-Language"))

	w.Header().Set("Access-Control-Allow-Origin", external)
	w.Header().Set("Content-Language", language)

	var session any
	if sessionData != "" {
		session = sessionData
	}

	s.render(w, http.StatusOK, pageData{
		Language:         language,
		IrmaServer:       external + target.Postfix,
		AssertURL:        s.cfg.Postfix + "/assert",
		ErrorAssertURL:   s.cfg.Postfix + "/errorassert",
		AssertParameters: paramsJWT,
		ErrorURL:         s.cfg.Postfix + "/report",
		SessionData:      session,
	})
}

// authenticate finds the service provider that issued the request and
// checks the query string signature with its keys. An unknown issuer, an
// unsigned request and a wrong signature are all refused.
func (s *server) authenticate(msg *saml.RedirectMessage, req *saml.AuthnRequest) (*saml.ServiceProvider, error) {
	if req.Issuer == "" {
		return nil, errors.New("the request has no issuer")
	}

	sp, ok := s.registry.Lookup(req.Issuer, s.now())
	if !ok {
		return nil, fmt.Errorf("no valid metadata for service provider %q", req.Issuer)
	}

	if err := msg.Verify(sp.SigningKeys); err != nil {
		return nil, err
	}

	return sp, nil
}

// showError answers with the page in its error state. The page reports the
// error back through /errorassert, with assertion parameters that only hold
// the error.
func (s *server) showError(w http.ResponseWriter, status int, message string) {
	paramsJWT, err := s.signParameters(&assertParameters{
		RequestError: &requestError{StatusCode: status, Message: message},
	})
	if err != nil {
		slog.Error("cannot sign the assertion parameters", "action", actionRequest, "error", err)
		writeText(w, http.StatusInternalServerError, "Internal error")

		return
	}

	s.render(w, status, pageData{
		ErrorAssertURL:   s.cfg.Postfix + "/errorassert",
		AssertParameters: paramsJWT,
		Error:            message,
		ErrorURL:         s.cfg.Postfix + "/report",
	})
}

func (s *server) render(w http.ResponseWriter, status int, data pageData) {
	var page strings.Builder
	if err := s.page.Execute(&page, data); err != nil {
		slog.Error("cannot render the page", "action", actionRequest, "error", err)
		writeText(w, http.StatusInternalServerError, "Internal error")

		return
	}

	w.Header().Set(headerContentType, contentTypeHTML)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(page.String()))
}

// condiscon decides which attributes to ask the user for. A request can say
// so in six ways:
//
//  1. nothing at all: the default condiscon from the configuration;
//  2. md:RequestedAttribute elements named after attribute identifiers, in a
//     req-attr RequestedAttributes extension;
//  3. a md:RequestedAttribute named "condiscon" holding condiscon JSON;
//  4. the same, named "signicat:param:condiscon";
//  5. a plain saml:Attribute named "condiscon" in the Extensions;
//  6. condiscon JSON as the Format of the NameIDPolicy.
func (s *server) condiscon(req *saml.AuthnRequest) ([][][]string, *requestError) {
	bad := func(message string) ([][][]string, *requestError) {
		return nil, &requestError{StatusCode: http.StatusBadRequest, Message: message}
	}

	var packed *string

	simple := map[string]map[string]bool{}

	for _, attribute := range req.Attributes {
		switch {
		case isAttributeIdentifier(attribute.Name):
			if !attribute.Requested {
				return bad(msgNotRequested)
			}

			credential := attribute.Name[:strings.LastIndex(attribute.Name, ".")]
			if simple[credential] == nil {
				simple[credential] = map[string]bool{}
			}

			if simple[credential][attribute.Name] {
				return bad(msgDuplicate)
			}

			simple[credential][attribute.Name] = true

		case strings.Contains(attribute.Name, "condiscon"):
			for _, value := range attribute.Values {
				if packed != nil {
					return bad(msgMultiple)
				}

				// Only a value typed xs:string is read, and one without
				// text counts as absent.
				if value.String && value.Text != "" {
					packed = &value.Text
				}
			}

		default:
			return bad(msgAttrName)
		}
	}

	switch {
	case len(simple) > 0:
		if packed != nil {
			return bad(msgMix)
		}

		// One disjunction per credential, holding all its attributes.
		condiscon := make([][][]string, 0, len(simple))

		for _, credential := range sortedSet(simple) {
			condiscon = append(condiscon, [][]string{sortedSet(simple[credential])})
		}

		return condiscon, nil

	case packed != nil:
		condiscon, err := parseCondiscon(*packed)
		if err != nil {
			return bad(msgCondiscon)
		}

		return condiscon, nil
	}

	if req.NameIDPolicyFormat != nil {
		if condiscon, err := parseCondiscon(*req.NameIDPolicyFormat); err == nil {
			return condiscon, nil
		}
	}

	return s.cfg.DefaultCondiscon, nil
}

// isAttributeIdentifier reports whether name has the four dot-separated
// parts of an IRMA attribute identifier. Empty parts at the end do not
// count, as in Java's String.split.
func isAttributeIdentifier(name string) bool {
	parts := strings.Split(name, ".")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	return len(parts) == 4
}

// parseCondiscon reads condiscon JSON: a list of disjunctions, each a list
// of conjunctions, each a list of attribute identifiers.
func parseCondiscon(s string) ([][][]string, error) {
	var condiscon [][][]string
	if err := json.Unmarshal([]byte(s), &condiscon); err != nil {
		return nil, err
	}

	if condiscon == nil {
		return nil, errors.New("condiscon is null")
	}

	return condiscon, nil
}

func sortedSet[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// sessionToken returns the requestor token from the session data of the
// IRMA server, or "".
func sessionToken(sessionData string) string {
	var data struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal([]byte(sessionData), &data); err != nil {
		return ""
	}

	return data.Token
}

// pageLanguage picks the language of the page. The Yivi frontend cannot
// switch language during a session, so it follows the browser: English when
// that is the language the browser prefers most, Dutch otherwise.
func pageLanguage(acceptLanguage string) string {
	best, bestQ := "", 0.0

	for part := range strings.SplitSeq(acceptLanguage, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0

		if _, value, ok := strings.Cut(strings.TrimSpace(params), "="); ok {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				continue
			}

			q = parsed
		}

		if q > bestQ {
			best, bestQ = strings.TrimSpace(tag), q
		}
	}

	primary, _, _ := strings.Cut(best, "-")
	if strings.EqualFold(primary, langEN) {
		return langEN
	}

	return langNL
}
