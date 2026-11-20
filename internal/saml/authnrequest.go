package saml

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

const nameIDFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

// ErrNotAuthnRequest is returned when the SAML message is something other
// than a SAML 2.0 AuthnRequest.
var ErrNotAuthnRequest = errors.New("saml: message is not an AuthnRequest")

// AuthnRequest holds the parts of an AuthnRequest the bridge uses.
type AuthnRequest struct {
	ID           string
	IssueInstant time.Time

	// Issuer is the entity ID of the service provider, or "" when the
	// request has no Issuer or one in a format other than entity.
	Issuer string

	// ACSURL is the AssertionConsumerServiceURL attribute, or "".
	ACSURL string

	// Destination is the Destination attribute, or "".
	Destination string

	// ProviderName is nil when the attribute is absent.
	ProviderName *string

	// NameIDPolicyFormat is nil when there is no NameIDPolicy or it has no
	// Format.
	NameIDPolicyFormat *string

	// Attributes are the attributes found in the Extensions, in document
	// order: those inside a req-attr RequestedAttributes element, and the
	// Attribute and RequestedAttribute elements placed directly in the
	// Extensions.
	Attributes []ExtensionAttribute
}

// ExtensionAttribute is an attribute a service provider put in the
// Extensions of its request.
type ExtensionAttribute struct {
	Name string

	// Requested is true for a md:RequestedAttribute and false for a plain
	// saml:Attribute.
	Requested bool

	// Values holds one entry per child element of the attribute.
	Values []ExtensionValue
}

// ExtensionValue is one value of an ExtensionAttribute.
type ExtensionValue struct {
	// String is true when the value is typed xsi:type="xs:string". OpenSAML
	// only read the text of such values, and so does the bridge.
	String bool

	// Text is the text of the value without surrounding white space.
	Text string
}

// ParseAuthnRequest reads an AuthnRequest. It checks that the document is
// one and that it has the ID, Version and IssueInstant every SAML 2.0
// request must have; everything else is for the caller to judge.
func ParseAuthnRequest(data []byte) (*AuthnRequest, error) {
	doc, err := parseXML(data, MaxRequestXMLBytes)
	if err != nil {
		return nil, err
	}

	root := doc.Root()
	if !is(root, nsProtocol, "AuthnRequest") {
		return nil, fmt.Errorf("%w: root element is %s", ErrNotAuthnRequest, root.FullTag())
	}

	req := &AuthnRequest{}

	req.ID, _ = attr(root, "ID")
	if req.ID == "" {
		return nil, fmt.Errorf("%w: AuthnRequest has no ID", ErrXML)
	}

	if version, _ := attr(root, "Version"); version != "2.0" {
		return nil, fmt.Errorf("%w: AuthnRequest has Version %q, not 2.0", ErrXML, version)
	}

	instant, ok := attr(root, "IssueInstant")
	if !ok {
		return nil, fmt.Errorf("%w: AuthnRequest has no IssueInstant", ErrXML)
	}

	req.IssueInstant, err = parseTime(instant)
	if err != nil {
		return nil, fmt.Errorf("%w: IssueInstant %q: %w", ErrXML, instant, err)
	}

	req.ACSURL, _ = attr(root, "AssertionConsumerServiceURL")
	req.Destination, _ = attr(root, "Destination")

	if name, ok := attr(root, "ProviderName"); ok {
		req.ProviderName = &name
	}

	if issuer := child(root, nsAssertion, "Issuer"); issuer != nil {
		// OpenSAML only took the Issuer as the peer's entity ID when its
		// Format was absent or the entity format.
		if format, ok := attr(issuer, "Format"); !ok || format == nameIDFormatEntity {
			req.Issuer = strings.TrimSpace(issuer.Text())
		}
	}

	if policy := child(root, nsProtocol, "NameIDPolicy"); policy != nil {
		if format, ok := attr(policy, "Format"); ok {
			req.NameIDPolicyFormat = &format
		}
	}

	if ext := child(root, nsProtocol, "Extensions"); ext != nil {
		req.Attributes = extensionAttributes(ext)
	}

	return req, nil
}

func extensionAttributes(ext *etree.Element) []ExtensionAttribute {
	var out []ExtensionAttribute

	for _, el := range ext.ChildElements() {
		switch {
		case is(el, nsReqAttr, "RequestedAttributes"):
			for _, ra := range children(el, nsMetadata, "RequestedAttribute") {
				out = append(out, extensionAttribute(ra, true))
			}
		case is(el, nsMetadata, "RequestedAttribute"):
			out = append(out, extensionAttribute(el, true))
		case is(el, nsAssertion, "Attribute"):
			out = append(out, extensionAttribute(el, false))
		}
	}

	return out
}

func extensionAttribute(el *etree.Element, requested bool) ExtensionAttribute {
	a := ExtensionAttribute{Requested: requested}
	a.Name, _ = attr(el, "Name")

	for _, v := range el.ChildElements() {
		a.Values = append(a.Values, ExtensionValue{String: isXSDString(v), Text: strings.TrimSpace(v.Text())})
	}

	return a
}
