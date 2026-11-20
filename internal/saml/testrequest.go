package saml

import (
	"time"

	"github.com/beevik/etree"
)

// TestRequest describes an AuthnRequest of the built-in test service
// provider. At most one of the request forms is set; with none of them the
// request asks for nothing and the bridge falls back to its default
// condiscon.
type TestRequest struct {
	Issuer       string
	IssueInstant time.Time

	// Attributes puts one md:RequestedAttribute per attribute identifier in
	// a req-attr RequestedAttributes extension.
	Attributes []string

	// CondisconName and Condiscon put the condiscon JSON in a
	// md:RequestedAttribute with that Name, inside RequestedAttributes.
	CondisconName string
	Condiscon     string

	// AttributeCondiscon puts the condiscon JSON in a plain saml:Attribute
	// named "condiscon", directly in the Extensions.
	AttributeCondiscon string

	// NameIDPolicyFormat carries the condiscon JSON as the Format of the
	// NameIDPolicy, the oldest of the request forms.
	NameIDPolicyFormat string
}

// AuthnRequestXML builds the AuthnRequest. Unlike the Java test service
// provider it gives the request an ID, which SAML requires and the bridge
// now insists on.
func (t TestRequest) AuthnRequestXML() ([]byte, error) {
	req := etree.NewElement("saml2p:AuthnRequest")
	req.CreateAttr("xmlns:saml2p", nsProtocol)
	req.CreateAttr(idAttribute, randomID())
	req.CreateAttr("IssueInstant", t.IssueInstant.UTC().Format(timeFormat))
	req.CreateAttr("Version", "2.0")

	issuer := req.CreateElement("saml2:Issuer")
	issuer.CreateAttr("xmlns:saml2", nsAssertion)
	issuer.SetText(t.Issuer)

	switch {
	case len(t.Attributes) > 0:
		requested := requestedAttributes(req)

		for _, name := range t.Attributes {
			ra := requestedAttribute(requested, name)
			ra.CreateAttr("isRequired", "true")
		}

	case t.CondisconName != "":
		addStringValue(requestedAttribute(requestedAttributes(req), t.CondisconName), t.Condiscon)

	case t.AttributeCondiscon != "":
		attribute := req.CreateElement("saml2p:Extensions").CreateElement("saml2:Attribute")
		attribute.CreateAttr("xmlns:saml2", nsAssertion)
		attribute.CreateAttr("Name", "condiscon")
		addStringValue(attribute, t.AttributeCondiscon)

	case t.NameIDPolicyFormat != "":
		req.CreateElement("saml2p:NameIDPolicy").CreateAttr("Format", t.NameIDPolicyFormat)
	}

	return marshal(req)
}

func requestedAttributes(req *etree.Element) *etree.Element {
	requested := req.CreateElement("saml2p:Extensions").CreateElement("req-attr:RequestedAttributes")
	requested.CreateAttr("xmlns:req-attr", nsReqAttr)

	return requested
}

func requestedAttribute(parent *etree.Element, name string) *etree.Element {
	ra := parent.CreateElement("md:RequestedAttribute")
	ra.CreateAttr("xmlns:md", nsMetadata)
	ra.CreateAttr("Name", name)

	return ra
}

func addStringValue(attribute *etree.Element, text string) {
	value := attribute.CreateElement("saml2:AttributeValue")
	value.CreateAttr("xmlns:saml2", nsAssertion)
	value.CreateAttr("xmlns:xsd", nsXSD)
	value.CreateAttr("xmlns:xsi", nsXSI)
	value.CreateAttr("xsi:type", "xsd:string")
	value.SetText(text)
}
