package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/privacybydesign/irma-saml-bridge/internal/disclosure"
	"github.com/privacybydesign/irma-saml-bridge/internal/replay"
	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/token"
)

const (
	actionAssert = "assert-flow"

	subjectParameters = "assert_parameters"
	claimParameters   = "aparams"

	msgBody            = "Invalid request body"
	msgIrmaToken       = "Invalid IRMA session result"
	msgParameters      = "Invalid assertion parameters"
	msgMalformed       = "Received malformed disclosure"
	msgNotValid        = "Expected valid proof and present attributes"
	msgNoMatch         = "The disclosure does not match the requested condiscon"
	msgOtherSession    = "The disclosure does not belong to this request"
	msgBusy            = "Too many requests are being answered, try again later"
	msgSign            = "Failed to write signature"
	msgWrite           = "Failed to write assertion"
	msgSelfCheck       = "Failed to validate signature or format of our assertion"
	msgFrontend        = "Something went wrong in the frontend"
	msgUserCancelled   = "The user cancelled."
	msgNoTestIrmaKey   = "testIrmaPrivateKeyPath is not configured"
	msgCondisconParams = "Invalid condiscon in assertion parameters"
)

// userCancelled is the error of /errorassert/abort.
var userCancelled = &requestError{StatusCode: http.StatusBadRequest, Message: msgUserCancelled}

// bridgeError is an error with the HTTP status and the text the caller gets.
type bridgeError struct {
	status  int
	message string
}

func (e *bridgeError) Error() string { return e.message }

// assertParameters is the state of a login. The bridge keeps nothing between
// /request and /assert: it signs this, gives it to the page, and gets it
// back. That is what lets every replica answer every request.
type assertParameters struct {
	SPName       string
	RequestID    string
	ServiceURL   string
	Issuer       string
	Condiscon    string
	RelayState   *string
	RequestError *requestError

	// IrmaToken is the requestor token of the IRMA session started for
	// this request. A session result with another token is not accepted.
	// The Java service did not record it.
	IrmaToken string

	// IssueInstant is the IssueInstant of the AuthnRequest, in Unix
	// seconds, or zero.
	IssueInstant int64
}

// claim returns the parameters as the "aparams" claim, with the names and
// types the Java service used, so that during a rolling update a token of
// one version is readable by the other.
func (p *assertParameters) claim() (map[string]any, error) {
	requestError, err := json.Marshal(p.RequestError)
	if err != nil {
		return nil, err
	}

	claim := map[string]any{
		"sp_name":       nullable(p.SPName),
		"request_id":    nullable(p.RequestID),
		"service_url":   nullable(p.ServiceURL),
		"issuer":        nullable(p.Issuer),
		"condiscon":     nullable(p.Condiscon),
		"relay_state":   nil,
		"request_error": string(requestError),
		"irma_token":    nullable(p.IrmaToken),
		"issue_instant": p.IssueInstant,
	}

	if p.RelayState != nil {
		claim["relay_state"] = *p.RelayState
	}

	return claim, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}

	return s
}

func (s *server) signParameters(p *assertParameters) (string, error) {
	claim, err := p.claim()
	if err != nil {
		return "", err
	}

	return token.Sign(s.keys.jwtPrivate, s.cfg.issuerName(), subjectParameters, claimParameters, claim, s.now())
}

// verifyParameters checks that a token was signed by the bridge as
// assertion parameters and reads them.
func (s *server) verifyParameters(tokenString string) (*assertParameters, error) {
	claims, err := token.Verify(tokenString, &s.keys.jwtPrivate.PublicKey, s.now)
	if err != nil {
		return nil, err
	}

	// The same key signs the session requests for the IRMA server. Only a
	// token made as assertion parameters is one.
	if sub, _ := claims["sub"].(string); sub != subjectParameters {
		return nil, errors.New("token is not for assertion parameters")
	}

	claim, ok := claims[claimParameters].(map[string]any)
	if !ok {
		return nil, errors.New("token has no assertion parameters")
	}

	p := &assertParameters{}
	p.SPName, _ = claim["sp_name"].(string)
	p.RequestID, _ = claim["request_id"].(string)
	p.ServiceURL, _ = claim["service_url"].(string)
	p.Issuer, _ = claim["issuer"].(string)
	p.Condiscon, _ = claim["condiscon"].(string)
	p.IrmaToken, _ = claim["irma_token"].(string)

	if relay, ok := claim["relay_state"].(string); ok {
		p.RelayState = &relay
	}

	if instant, ok := claim["issue_instant"].(float64); ok {
		p.IssueInstant = int64(instant)
	}

	if encoded, ok := claim["request_error"].(string); ok {
		if err := json.Unmarshal([]byte(encoded), &p.RequestError); err != nil {
			return nil, errors.New("token has a malformed request error")
		}
	}

	return p, nil
}

// redirectInstruction tells the page where to post which SAML Response.
type redirectInstruction struct {
	// SAMLResponse is the signed Response, base64 encoded.
	SAMLResponse string `json:"samlResponse"`

	// ServiceURL is the AssertionConsumerService to post it to.
	ServiceURL *string `json:"serviceUrl"`

	// RelayState is handed back to the service provider as it came.
	RelayState *string `json:"relayState"`
}

type assertRequest struct {
	// Parameters is the assertion parameters JWT the page was given.
	Parameters string `json:"parameters"`

	// Token is the session result JWT of the IRMA server.
	Token string `json:"token"`
}

// handleAssert turns the result of an IRMA session into a SAML Response.
func (s *server) handleAssert(w http.ResponseWriter, r *http.Request) {
	var body assertRequest
	if err := decodeJSON(w, r, maxAssertBody, &body); err != nil {
		slog.Warn(msgBody, "action", actionAssert, "error", err)
		writeText(w, http.StatusBadRequest, msgBody)

		return
	}

	instruction, _, berr := s.assert(body, true)
	if berr != nil {
		writeText(w, berr.status, berr.message)

		return
	}

	writeJSON(w, http.StatusOK, instruction)
}

// assert checks a session result against the assertion parameters and makes
// the Response. It also returns the Response as XML.
func (s *server) assert(body assertRequest, once bool) (*redirectInstruction, []byte, *bridgeError) {
	fail := func(status int, message string, err error) (*redirectInstruction, []byte, *bridgeError) {
		slog.Warn(message, "action", actionAssert, "error", err)

		return nil, nil, &bridgeError{status: status, message: message}
	}

	// The session result must be signed by the IRMA server, and still valid.
	irmaClaims, err := token.Verify(body.Token, s.keys.irmaPublic, s.now)
	if err != nil {
		return fail(http.StatusUnauthorized, msgIrmaToken, err)
	}

	params, err := s.verifyParameters(body.Parameters)
	if err != nil {
		return fail(http.StatusUnauthorized, msgParameters, err)
	}

	disclosed, err := disclosure.FromClaims(irmaClaims)
	if err != nil {
		return fail(http.StatusBadRequest, msgMalformed, err)
	}

	if len(disclosed.Attributes) == 0 || disclosed.ProofStatus != disclosure.ProofValid {
		return fail(http.StatusUnauthorized, msgNotValid, nil)
	}

	condiscon, err := parseCondiscon(params.Condiscon)
	if err != nil {
		return fail(http.StatusInternalServerError, msgCondisconParams, err)
	}

	if !disclosed.Fulfills(condiscon) {
		return fail(http.StatusUnauthorized, msgNoMatch, nil)
	}

	// The result must come from the session that was started for this
	// request, not from another session of the same IRMA server.
	if params.IrmaToken == "" || disclosed.Token != params.IrmaToken {
		return fail(http.StatusUnauthorized, msgOtherSession, nil)
	}

	if once && params.RequestID != "" {
		if err := s.answered.Consume(replay.Key(params.Issuer, params.RequestID), s.rememberUntil(params)); err != nil {
			if errors.Is(err, replay.ErrReplayed) {
				return fail(http.StatusConflict, msgAnswered, err)
			}

			return fail(http.StatusServiceUnavailable, msgBusy, err)
		}
	}

	instruction, xml, berr := s.redirectInstruction(params, saml.ResponseParams{
		Success:      true,
		Attributes:   disclosed.Attributes,
		SessionToken: disclosed.Token,
	})
	if berr != nil {
		return nil, nil, berr
	}

	slog.Info("disclosed successfully", "action", "disclosedsuccesfully",
		"attributes", sortedSet(disclosed.Attributes), "serviceprovider", params.SPName)

	return instruction, xml, nil
}

// rememberUntil is how long an answered request is remembered: as long as
// the request itself is accepted, and at least one request lifetime from
// now, which outlives the IRMA session it was answered with.
func (s *server) rememberUntil(params *assertParameters) time.Time {
	from := s.now()
	if issued := time.Unix(params.IssueInstant, 0); params.IssueInstant != 0 && issued.After(from) {
		from = issued
	}

	return from.Add(s.cfg.requestTTL()).Add(time.Minute)
}

// handleErrorAssert makes a SAML Response that tells the service provider
// the login failed. With override set, that is the reason; otherwise it is
// the error in the assertion parameters, if any.
func (s *server) handleErrorAssert(override *requestError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body assertRequest
		if err := decodeJSON(w, r, maxAssertBody, &body); err != nil {
			slog.Warn(msgBody, "action", actionAssert, "error", err)
			writeText(w, http.StatusBadRequest, msgBody)

			return
		}

		instruction, _, berr := s.errorAssert(body, override)
		if berr != nil {
			writeText(w, berr.status, berr.message)

			return
		}

		writeJSON(w, http.StatusOK, instruction)
	}
}

func (s *server) errorAssert(body assertRequest, override *requestError) (*redirectInstruction, []byte, *bridgeError) {
	params, err := s.verifyParameters(body.Parameters)
	if err != nil {
		slog.Warn(msgParameters, "action", actionAssert, "error", err)

		return nil, nil, &bridgeError{status: http.StatusUnauthorized, message: msgParameters}
	}

	reason := params.RequestError
	if override != nil {
		reason = override
	}

	if reason == nil {
		// The page ran into something it cannot name.
		reason = &requestError{StatusCode: http.StatusBadRequest, Message: msgFrontend}
	}

	instruction, xml, berr := s.redirectInstruction(params, saml.ResponseParams{StatusMessage: reason.Message})
	if berr != nil {
		return nil, nil, berr
	}

	slog.Info("disclosure failed", "action", "disclosederror", "serviceprovider", params.SPName)

	return instruction, xml, nil
}

// redirectInstruction builds, signs and checks the Response for the request
// the parameters describe.
func (s *server) redirectInstruction(params *assertParameters, p saml.ResponseParams) (*redirectInstruction, []byte, *bridgeError) {
	const action = "redirectinstruction.create"

	fail := func(message string, err error) (*redirectInstruction, []byte, *bridgeError) {
		slog.Error(message, "action", action, "error", err)

		return nil, nil, &bridgeError{status: http.StatusInternalServerError, message: message}
	}

	p.RequestID = params.RequestID
	p.ServiceURL = params.ServiceURL
	p.Audience = params.Issuer
	p.Now = s.now()
	p.Lifetime = s.cfg.responseTTL()

	response := s.responder.NewResponse(p)

	if err := s.responder.Sign(response); err != nil {
		return fail(msgSign, err)
	}

	xml, err := s.responder.Marshal(response)
	if err != nil {
		return fail(msgWrite, err)
	}

	// Every Response is verified with the bridge's own certificate before
	// it leaves, so a Response that a service provider would reject is
	// never handed out.
	if err := s.responder.Verify(xml); err != nil {
		return fail(msgSelfCheck, err)
	}

	instruction := &redirectInstruction{
		SAMLResponse: base64.StdEncoding.EncodeToString(xml),
		RelayState:   params.RelayState,
	}

	if params.ServiceURL != "" {
		instruction.ServiceURL = &params.ServiceURL
	}

	return instruction, xml, nil
}
