package saml

import (
	"encoding/base64"

	"github.com/beevik/etree"
)

// cacheDuration is the 30 seconds the Java service published, in the
// notation it used.
const cacheDuration = "P0Y0M0DT0H0M30.000S"

// Metadata returns the metadata of the identity provider: its entity ID, its
// signing certificate and the single sign-on service at ssoURL, which only
// takes the HTTP-Redirect binding. The document is not signed.
func (idp *IdentityProvider) Metadata(ssoURL string) ([]byte, error) {
	entity := idp.entityDescriptor()

	role := entity.CreateElement("md:IDPSSODescriptor")
	role.CreateAttr("WantAuthnRequestsSigned", "true")
	role.CreateAttr("protocolSupportEnumeration", nsProtocol)
	idp.addSigningKey(role)

	sso := role.CreateElement("md:SingleSignOnService")
	sso.CreateAttr("Binding", BindingRedirect)
	sso.CreateAttr("Location", ssoURL)

	return marshal(entity)
}

// TestSPMetadata returns metadata for the built-in test service provider.
// It has the entity ID and the certificate of the identity provider, because
// the test service provider signs its requests with the same key.
func (idp *IdentityProvider) TestSPMetadata(acsURL, organizationURL string) ([]byte, error) {
	entity := idp.entityDescriptor()

	role := entity.CreateElement("md:SPSSODescriptor")
	role.CreateAttr("WantAssertionsSigned", "true")
	role.CreateAttr("protocolSupportEnumeration", nsProtocol)
	idp.addSigningKey(role)

	org := role.CreateElement("md:Organization")

	for _, part := range []struct{ tag, text string }{
		{"md:OrganizationName", "SIDN"},
		{"md:OrganizationDisplayName", "SIDN"},
		{"md:OrganizationURL", organizationURL},
	} {
		el := org.CreateElement(part.tag)
		el.CreateAttr("xml:lang", "en")
		el.SetText(part.text)
	}

	acs := role.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", BindingRedirect)
	acs.CreateAttr("Location", acsURL)
	acs.CreateAttr("index", "0")

	return marshal(entity)
}

func (idp *IdentityProvider) entityDescriptor() *etree.Element {
	entity := etree.NewElement("md:EntityDescriptor")
	entity.CreateAttr("xmlns:md", nsMetadata)
	entity.CreateAttr("cacheDuration", cacheDuration)
	entity.CreateAttr("entityID", idp.entityID)

	return entity
}

func (idp *IdentityProvider) addSigningKey(role *etree.Element) {
	key := role.CreateElement("md:KeyDescriptor")
	key.CreateAttr("use", "signing")

	info := key.CreateElement("ds:KeyInfo")
	info.CreateAttr("xmlns:ds", nsDSig)
	info.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(idp.cert.Raw))
}

func marshal(root *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.WriteSettings = canonicalWriteSettings
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(root)

	return doc.WriteToBytes()
}
