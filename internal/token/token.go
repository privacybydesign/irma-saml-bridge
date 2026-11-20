// Package token signs and verifies the JWTs of the bridge: the session
// request it sends to the IRMA server, the session result the IRMA server
// signs, and the assertion parameters the bridge hands to the browser and
// gets back.
package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalid is returned for a token that does not verify: a bad signature,
// another algorithm than RSA with SHA-2, or one that is expired or not yet
// valid.
var ErrInvalid = errors.New("token: invalid JWT")

// validMethods are the algorithms a token may be signed with. The IRMA
// server and the bridge both sign with RS256.
var validMethods = []string{"RS256", "RS384", "RS512"}

// Sign returns an RS256 JWT with the claims iat, iss and sub, and one more
// claim holding the payload. This is the shape of an IRMA requestor JWT.
func Sign(key *rsa.PrivateKey, issuer, subject, claimName string, claim any, now time.Time) (string, error) {
	return SignClaims(key, issuer, subject, map[string]any{claimName: claim}, now)
}

// SignClaims returns an RS256 JWT with the claims iat, iss and sub next to
// the given ones.
func SignClaims(key *rsa.PrivateKey, issuer, subject string, claims map[string]any, now time.Time) (string, error) {
	all := jwt.MapClaims{}
	maps.Copy(all, claims)

	all["iat"] = now.Unix()
	all["iss"] = issuer
	all["sub"] = subject

	return jwt.NewWithClaims(jwt.SigningMethodRS256, all).SignedString(key)
}

// Verify checks the signature of a JWT with key and returns its claims. A
// token with an exp or nbf claim is only accepted between those times.
func Verify(tokenString string, key *rsa.PublicKey, now func() time.Time) (map[string]any, error) {
	parser := jwt.NewParser(jwt.WithValidMethods(validMethods), jwt.WithTimeFunc(now))

	claims := jwt.MapClaims{}

	_, err := parser.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return claims, nil
}
