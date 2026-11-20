package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
	"github.com/privacybydesign/irma-saml-bridge/internal/testkeys"
)

// These tests put gosaml2, a service provider library that shares no code
// with package saml, on the other side: it must accept the Responses the
// bridge signs, and the bridge must accept the requests it signs.

const (
	idpEntityID = "https://bridge.example/metadata"
	idpSSOURL   = "https://bridge.example/saml-bridge/request"
	spEntityID  = "https://sp.example/metadata"
	spACSURL    = "https://sp.example/acs"

	// A value with characters that need escaping. A carriage return is not
	// in it: gosaml2 loses those when it reads the attributes after it has
	// verified the signature. TestSignatureSurvivesAwkwardValues covers it.
	fullName = `Zoë Çelik-de Vries <b> & "Jr." 🙂`
)

type keyStore struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (k keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.cert.Raw, nil }

func independentSP(t *testing.T, idpCert *x509.Certificate) *saml2.SAMLServiceProvider {
	t.Helper()

	spKey := testkeys.Key(t, "sp")

	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idpSSOURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      idpEntityID,
		ServiceProviderIssuer:       spEntityID,
		AssertionConsumerServiceURL: spACSURL,
		AudienceURI:                 spEntityID,
		SignAuthnRequests:           true,
		SignAuthnRequestsAlgorithm:  dsig.RSASHA256SignatureMethod,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}},
		SPKeyStore:                  keyStore{key: spKey, cert: testkeys.ValidCertificate(t, spKey, "sp")},
	}
}

func identityProvider(t *testing.T) (*saml.IdentityProvider, *x509.Certificate) {
	t.Helper()

	key := testkeys.Key(t, "idp")
	cert := testkeys.ValidCertificate(t, key, "idp")

	idp, err := saml.NewIdentityProvider(idpEntityID, key, cert)
	require.NoError(t, err)

	return idp, cert
}

func login() saml.ResponseParams {
	return saml.ResponseParams{
		RequestID:  "_request",
		ServiceURL: spACSURL,
		Audience:   spEntityID,
		Now:        time.Now(),
		Lifetime:   360 * time.Second,
		Success:    true,
		Attributes: map[string]string{
			"pbdf.sidn-pbdf.email.email":               "user@example.com",
			"pbdf.sidn-pbdf.mobilenumber.mobilenumber": "+31612345678",
			"pbdf.gemeente.personalData.fullname":      fullName,
		},
		SessionToken: "KzxuWKwL5KGLKr4uerws",
	}
}

func encode(t *testing.T, idp *saml.IdentityProvider, p saml.ResponseParams) string {
	t.Helper()

	response := idp.NewResponse(p)
	require.NoError(t, idp.Sign(response))

	xml, err := response.XML()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(xml)
}

func TestIndependentSPAcceptsResponse(t *testing.T) {
	idp, cert := identityProvider(t)
	sp := independentSP(t, cert)

	info, err := sp.RetrieveAssertionInfo(encode(t, idp, login()))
	require.NoError(t, err)

	assert.True(t, info.ResponseSignatureValidated)
	assert.False(t, info.WarningInfo.InvalidTime)
	assert.False(t, info.WarningInfo.NotInAudience)

	// The NameID is the value of the first attribute by identifier.
	assert.Equal(t, fullName, info.NameID)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", info.NameIDFormat)

	assert.Equal(t, "user@example.com", info.Values.Get("pbdf.sidn-pbdf.email.email"))
	assert.Equal(t, "+31612345678", info.Values.Get("pbdf.sidn-pbdf.mobilenumber.mobilenumber"))
	assert.Equal(t, fullName, info.Values.Get("pbdf.gemeente.personalData.fullname"))
	assert.Len(t, info.Values, 3)

	require.Len(t, info.Assertions, 1)
	assert.Equal(t, idpEntityID, info.Assertions[0].Issuer.Value)
	assert.Equal(t, "_request", info.Assertions[0].Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo)
}

func TestIndependentSPRejectsWhatItShould(t *testing.T) {
	idp, cert := identityProvider(t)

	otherKey := testkeys.Key(t, "other")
	other, err := saml.NewIdentityProvider(idpEntityID, otherKey, testkeys.ValidCertificate(t, otherKey, "other"))
	require.NoError(t, err)

	tamper := func(encoded, old, replacement string) string {
		xml, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)
		require.Contains(t, string(xml), old)

		return base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(xml), old, replacement, 1)))
	}

	valid := encode(t, idp, login())

	failed := login()
	failed.Success = false
	failed.StatusMessage = "The user cancelled."

	tests := map[string]string{
		"signed with another key": encode(t, other, login()),
		"changed attribute":       tamper(valid, "user@example.com</saml2:AttributeValue>", "admin@example.com</saml2:AttributeValue>"),
		"changed audience":        tamper(valid, "<saml2:Audience>"+spEntityID, "<saml2:Audience>https://other.example"),
		"failed login":            encode(t, idp, failed),
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := independentSP(t, cert).RetrieveAssertionInfo(encoded)
			require.Error(t, err)
		})
	}

	t.Run("other audience", func(t *testing.T) {
		p := login()
		p.Audience = "https://other.example/metadata"

		info, err := independentSP(t, cert).RetrieveAssertionInfo(encode(t, idp, p))
		require.NoError(t, err)
		assert.True(t, info.WarningInfo.NotInAudience)
	})

	t.Run("other destination", func(t *testing.T) {
		p := login()
		p.ServiceURL = "https://other.example/acs"

		_, err := independentSP(t, cert).RetrieveAssertionInfo(encode(t, idp, p))
		require.Error(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		p := login()
		p.Now = time.Now().Add(-time.Hour)

		_, err := independentSP(t, cert).RetrieveAssertionInfo(encode(t, idp, p))
		require.ErrorContains(t, err, "NotOnOrAfter")
	})
}

// A request the independent service provider signs for the HTTP-Redirect
// binding is decoded, verified with the key from its own metadata, and
// parsed.
func TestBridgeAcceptsRequestOfIndependentSP(t *testing.T) {
	_, cert := identityProvider(t)
	sp := independentSP(t, cert)

	metadata, err := sp.Metadata()
	require.NoError(t, err)

	metadataXML, err := xmlMarshal(metadata)
	require.NoError(t, err)

	sps, err := saml.ParseMetadata(metadataXML)
	require.NoError(t, err)
	require.Len(t, sps, 1)

	registered := sps[0]
	assert.Equal(t, spEntityID, registered.EntityID)
	assert.True(t, registered.HasACS(spACSURL))
	require.Len(t, registered.SigningKeys, 1)

	doc, err := sp.BuildAuthRequestDocumentNoSig()
	require.NoError(t, err)

	redirect, err := sp.BuildAuthURLRedirect("relay state/1", doc)
	require.NoError(t, err)

	target, err := url.Parse(redirect)
	require.NoError(t, err)

	msg, err := saml.DecodeRedirect(target.RawQuery)
	require.NoError(t, err)
	require.NoError(t, msg.Verify(registered.SigningKeys))

	require.NotNil(t, msg.RelayState)
	assert.Equal(t, "relay state/1", *msg.RelayState)

	req, err := saml.ParseAuthnRequest(msg.XML)
	require.NoError(t, err)

	assert.Equal(t, spEntityID, req.Issuer)
	assert.Equal(t, spACSURL, req.ACSURL)
	assert.Equal(t, idpSSOURL, req.Destination)
	assert.NotEmpty(t, req.ID)
	assert.WithinDuration(t, time.Now(), req.IssueInstant, time.Minute)

	// Signed by someone else, it is refused.
	stranger := []*rsa.PublicKey{&testkeys.Key(t, "stranger").PublicKey}
	require.ErrorIs(t, msg.Verify(stranger), saml.ErrSignature)
}
