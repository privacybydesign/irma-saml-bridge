package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	paramSAMLRequest  = "SAMLRequest"
	paramSAMLEncoding = "SAMLEncoding"
	paramRelayState   = "RelayState"
	paramSigAlg       = "SigAlg"
	paramSignature    = "Signature"

	encodingDeflate = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"

	// SigAlgRSASHA256 is the algorithm the built-in test service provider
	// signs with.
	SigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// redirectSigAlgs are the SigAlg values a request may be signed with. The
// Java service put no limit on the algorithm, so it also took SHA-1 and MD5.
var redirectSigAlgs = map[string]crypto.Hash{
	SigAlgRSASHA256: crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": crypto.SHA512,
}

var (
	// ErrDecode is returned for a query that does not hold a readable
	// DEFLATE encoded SAML request.
	ErrDecode = errors.New("saml: cannot decode request")

	// ErrSignature is returned for a request that is not signed, or whose
	// signature does not verify with a key of the service provider.
	ErrSignature = errors.New("saml: request signature not accepted")
)

// RedirectMessage is a message received with the HTTP-Redirect binding.
type RedirectMessage struct {
	// XML is the inflated SAML message.
	XML []byte

	// RelayState is nil when the query has no RelayState parameter.
	RelayState *string

	sigAlg     string
	signature  []byte
	signedData string
}

// Signed reports whether the query carries a Signature.
func (m *RedirectMessage) Signed() bool { return len(m.signature) > 0 }

// SigAlg returns the signature algorithm the query names.
func (m *RedirectMessage) SigAlg() string { return m.sigAlg }

// DecodeRedirect reads a SAML request from the raw query string of a GET
// request (SAML bindings §3.4.4.1).
//
// The query is split once. The message, the relay state and the octets the
// signature covers all come from the same parameters, so a repeated
// SAMLRequest cannot be verified as one value and read as another. A query
// that repeats one of the SAML parameters is refused.
func DecodeRedirect(rawQuery string) (*RedirectMessage, error) {
	raw, err := samlParams(rawQuery)
	if err != nil {
		return nil, err
	}

	if enc, ok := raw[paramSAMLEncoding]; ok {
		value, err := url.QueryUnescape(enc)
		if err != nil {
			return nil, fmt.Errorf("%w: SAMLEncoding: %w", ErrDecode, err)
		}

		if v := strings.TrimSpace(value); v != "" && v != encodingDeflate {
			return nil, fmt.Errorf("%w: unsupported SAMLEncoding %q", ErrDecode, v)
		}
	}

	rawRequest, ok := raw[paramSAMLRequest]
	if !ok || rawRequest == "" {
		return nil, fmt.Errorf("%w: no SAMLRequest parameter", ErrDecode)
	}

	encoded, err := url.QueryUnescape(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: SAMLRequest: %w", ErrDecode, err)
	}

	deflated, err := decodeBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: SAMLRequest: %w", ErrDecode, err)
	}

	xmlBytes, err := inflate(deflated, MaxRequestXMLBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}

	msg := &RedirectMessage{XML: xmlBytes}

	// The signature covers the parameters as they were sent, still
	// percent-encoded, in this order.
	signed := paramSAMLRequest + "=" + rawRequest

	if rawRelay, ok := raw[paramRelayState]; ok {
		relay, err := url.QueryUnescape(rawRelay)
		if err != nil {
			return nil, fmt.Errorf("%w: RelayState: %w", ErrDecode, err)
		}

		msg.RelayState = &relay
		signed += "&" + paramRelayState + "=" + rawRelay
	}

	if rawAlg, ok := raw[paramSigAlg]; ok {
		alg, err := url.QueryUnescape(rawAlg)
		if err != nil {
			return nil, fmt.Errorf("%w: SigAlg: %w", ErrDecode, err)
		}

		msg.sigAlg = alg
		signed += "&" + paramSigAlg + "=" + rawAlg
	}

	if rawSig, ok := raw[paramSignature]; ok && rawSig != "" {
		value, err := url.QueryUnescape(rawSig)
		if err != nil {
			return nil, fmt.Errorf("%w: Signature: %w", ErrDecode, err)
		}

		sig, err := decodeBase64(value)
		if err != nil {
			return nil, fmt.Errorf("%w: Signature: %w", ErrDecode, err)
		}

		msg.signature = sig
	}

	msg.signedData = signed

	return msg, nil
}

// samlParams returns the raw, still encoded value of each SAML parameter in
// the query.
func samlParams(rawQuery string) (map[string]string, error) {
	out := map[string]string{}

	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}

		rawKey, rawValue, _ := strings.Cut(part, "=")

		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed query", ErrDecode)
		}

		switch key {
		case paramSAMLRequest, paramSAMLEncoding, paramRelayState, paramSigAlg, paramSignature:
		default:
			continue
		}

		// The name itself must not be encoded: the signed octets are found
		// by the literal name.
		if key != rawKey {
			return nil, fmt.Errorf("%w: parameter name %q is encoded", ErrDecode, rawKey)
		}

		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: parameter %s is repeated", ErrDecode, key)
		}

		out[key] = rawValue
	}

	return out, nil
}

// decodeBase64 reads standard base64, with or without padding, ignoring the
// white space some senders wrap it with.
func decodeBase64(s string) ([]byte, error) {
	s = stripSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}

	return base64.RawStdEncoding.DecodeString(s)
}

// inflate decompresses raw DEFLATE data, refusing output over limit bytes.
func inflate(data []byte, limit int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = r.Close() }()

	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot inflate: %w", err)
	}

	if len(out) > limit {
		return nil, fmt.Errorf("%w: inflated request is more than %d bytes", ErrXML, limit)
	}

	return out, nil
}

// Verify checks the query string signature with the signing keys of the
// service provider that issued the message. A message without a signature
// or SigAlg is refused, and so is an algorithm that is not RSA with SHA-256,
// SHA-384 or SHA-512.
func (m *RedirectMessage) Verify(keys []*rsa.PublicKey) error {
	if !m.Signed() {
		return fmt.Errorf("%w: the request is not signed", ErrSignature)
	}

	if m.sigAlg == "" {
		return fmt.Errorf("%w: no SigAlg parameter", ErrSignature)
	}

	hash, ok := redirectSigAlgs[m.sigAlg]
	if !ok {
		return fmt.Errorf("%w: SigAlg %q is not supported", ErrSignature, m.sigAlg)
	}

	if len(keys) == 0 {
		return fmt.Errorf("%w: the service provider has no signing key", ErrSignature)
	}

	h := hash.New()
	h.Write([]byte(m.signedData))
	digest := h.Sum(nil)

	for _, key := range keys {
		if rsa.VerifyPKCS1v15(key, hash, digest, m.signature) == nil {
			return nil
		}
	}

	return fmt.Errorf("%w: the signature does not match a key in the metadata", ErrSignature)
}

// EncodeRedirect builds the signed query string for sending xmlBytes with
// the HTTP-Redirect binding. Only the built-in test service provider and the
// tests send requests; the bridge itself only receives them.
func EncodeRedirect(xmlBytes []byte, relayState *string, key *rsa.PrivateKey) (string, error) {
	var deflated bytes.Buffer

	w, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", err
	}

	if _, err := w.Write(xmlBytes); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	query := paramSAMLRequest + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if relayState != nil {
		query += "&" + paramRelayState + "=" + url.QueryEscape(*relayState)
	}

	query += "&" + paramSigAlg + "=" + url.QueryEscape(SigAlgRSASHA256)

	digest := crypto.SHA256.New()
	digest.Write([]byte(query))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest.Sum(nil))
	if err != nil {
		return "", err
	}

	return query + "&" + paramSignature + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
}
