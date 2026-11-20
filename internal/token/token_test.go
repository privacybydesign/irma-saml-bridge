package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

func segment(v any) string {
	data, _ := json.Marshal(v)

	return base64.RawURLEncoding.EncodeToString(data)
}

// Counterpart of JwtUtilTest.selfSignedTokenVerifiesWithDerivedPublicKey.
func TestSignedTokenVerifiesWithPublicKey(t *testing.T) {
	key := testkeys.Key(t, "jwt")

	signed, err := Sign(key, "sidn-irma-saml-bridge", "assert_parameters", "aparams", "value", now)
	require.NoError(t, err)

	claims, err := Verify(signed, &key.PublicKey, clock)
	require.NoError(t, err)

	assert.Equal(t, "assert_parameters", claims["sub"])
	assert.Equal(t, "sidn-irma-saml-bridge", claims["iss"])
	assert.Equal(t, "value", claims["aparams"])
	assert.InDelta(t, float64(now.Unix()), claims["iat"], 0)

	// The IRMA server only takes RS256, whatever the size of the key.
	header, err := base64.RawURLEncoding.DecodeString(strings.Split(signed, ".")[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"alg":"RS256","typ":"JWT"}`, string(header))
}

// Counterpart of JwtUtilTest.irmaTokenVerifiesWithIrmaPublicKey.
func TestSignClaimsKeepsTheClaims(t *testing.T) {
	key := testkeys.Key(t, "irma")

	signed, err := SignClaims(key, "irmaserver", "disclosing_result", map[string]any{
		"proofStatus": "VALID",
		"token":       "session-token",
	}, now)
	require.NoError(t, err)

	claims, err := Verify(signed, &key.PublicKey, clock)
	require.NoError(t, err)

	assert.Equal(t, "VALID", claims["proofStatus"])
	assert.Equal(t, "session-token", claims["token"])
	assert.Equal(t, "irmaserver", claims["iss"])
	assert.Equal(t, "disclosing_result", claims["sub"])
}

// A session result is only accepted when it carries a signature made with
// the key of the IRMA server.
func TestVerifyRejectsOtherKey(t *testing.T) {
	signed, err := Sign(testkeys.Key(t, "attacker"), "irmaserver", "disclosing_result", "proofStatus", "VALID", now)
	require.NoError(t, err)

	_, err = Verify(signed, &testkeys.Key(t, "irma").PublicKey, clock)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key := testkeys.Key(t, "irma")

	signed, err := Sign(key, "irmaserver", "disclosing_result", "proofStatus", "INVALID", now)
	require.NoError(t, err)

	parts := strings.Split(signed, ".")
	parts[1] = segment(map[string]any{"proofStatus": "VALID", "iat": now.Unix()})

	_, err = Verify(strings.Join(parts, "."), &key.PublicKey, clock)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestVerifyRejectsUnsignedAndSymmetricTokens(t *testing.T) {
	key := testkeys.Key(t, "irma")
	payload := segment(map[string]any{"proofStatus": "VALID"})

	// "alg":"none" has no signature at all.
	none := segment(map[string]string{"alg": "none"}) + "." + payload + "."

	// HS256 with the public key as the secret: the algorithm confusion
	// attack on libraries that let the token choose how it is verified.
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	unsigned := segment(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + payload
	mac := hmac.New(sha256.New, public)
	mac.Write([]byte(unsigned))
	confused := unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// PS256 is RSA too, but not what either side signs with.
	pss, err := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims{"proofStatus": "VALID"}).SignedString(key)
	require.NoError(t, err)

	for name, tokenString := range map[string]string{
		"none":      none,
		"HS256":     confused,
		"PS256":     pss,
		"empty":     "",
		"garbage":   "a.b.c",
		"two parts": "a.b",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(tokenString, &key.PublicKey, clock)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

// The IRMA server gives its session result a validity of 30 seconds. After
// that it is refused.
func TestVerifyHonoursExpiryAndNotBefore(t *testing.T) {
	key := testkeys.Key(t, "irma")

	sign := func(claims map[string]any) string {
		signed, err := SignClaims(key, "irmaserver", "disclosing_result", claims, now)
		require.NoError(t, err)

		return signed
	}

	valid := sign(map[string]any{"exp": now.Add(30 * time.Second).Unix()})

	_, err := Verify(valid, &key.PublicKey, clock)
	require.NoError(t, err)

	_, err = Verify(valid, &key.PublicKey, func() time.Time { return now.Add(29 * time.Second) })
	require.NoError(t, err)

	_, err = Verify(valid, &key.PublicKey, func() time.Time { return now.Add(31 * time.Second) })
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, err, jwt.ErrTokenExpired)

	_, err = Verify(sign(map[string]any{"nbf": now.Add(time.Minute).Unix()}), &key.PublicKey, clock)
	require.ErrorIs(t, err, jwt.ErrTokenNotValidYet)

	// Without exp, as the bridge's own assertion parameters, a token does
	// not expire.
	_, err = Verify(sign(nil), &key.PublicKey, func() time.Time { return now.AddDate(1, 0, 0) })
	require.NoError(t, err)
}

func TestVerifyAcceptsRS384AndRS512(t *testing.T) {
	key := testkeys.Key(t, "irma")

	for _, method := range []jwt.SigningMethod{jwt.SigningMethodRS384, jwt.SigningMethodRS512} {
		signed, err := jwt.NewWithClaims(method, jwt.MapClaims{"proofStatus": "VALID"}).SignedString(key)
		require.NoError(t, err)

		_, err = Verify(signed, &key.PublicKey, clock)
		require.NoError(t, err, method.Alg())
	}
}
