package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/moov-io/signedxml"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	statusSuccess     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusResponder   = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	statusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	nameIDTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	confirmationBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	authnContextClass  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

	// timeFormat is how OpenSAML wrote instants: UTC with milliseconds.
	timeFormat = "2006-01-02T15:04:05.000Z"

	idAttribute = "ID"

	algExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped     = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algSHA256        = "http://www.w3.org/2001/04/xmlenc#sha256"

	// xsdPrefix is the prefix the Response declares for XML Schema.
	xsdPrefix = "xsd"
)

// IdentityProvider signs the Responses of the bridge and describes it in
// metadata.
type IdentityProvider struct {
	entityID string
	key      *rsa.PrivateKey
	cert     *x509.Certificate
}

// NewIdentityProvider returns an identity provider that signs with key and
// publishes cert. The two must belong together.
func NewIdentityProvider(entityID string, key *rsa.PrivateKey, cert *x509.Certificate) (*IdentityProvider, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the SAML certificate does not hold an RSA key")
	}

	if !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the SAML private key does not belong to the SAML certificate")
	}

	return &IdentityProvider{entityID: entityID, key: key, cert: cert}, nil
}

// ResponseParams is what a Response is made from.
type ResponseParams struct {
	// RequestID is the ID of the AuthnRequest that is answered.
	RequestID string

	// ServiceURL is the AssertionConsumerService the Response is for.
	ServiceURL string

	// Audience is the entity ID of the service provider.
	Audience string

	// Now is the IssueInstant, and Lifetime how long the assertion is valid
	// after it.
	Now      time.Time
	Lifetime time.Duration

	// Success selects a Response with an assertion. Without it the Response
	// has the status Responder / AuthnFailed and carries StatusMessage.
	Success       bool
	StatusMessage string

	// Attributes are the disclosed attributes, by attribute identifier.
	Attributes map[string]string

	// SessionToken is the IRMA session token. The assertion ID is derived
	// from it; without one the ID is random.
	SessionToken string
}

// Response is a SAML Response that is being made.
type Response struct {
	el *etree.Element

	// inclusivePrefixes are the namespace prefixes that the Response only
	// uses inside a value, where canonicalization does not see them.
	inclusivePrefixes string

	signed bool
}

// NewResponse builds the Response, unsigned. Elements, attributes and their
// order are those of the Java service.
func (idp *IdentityProvider) NewResponse(p ResponseParams) *Response {
	now := p.Now.UTC()
	instant := now.Format(timeFormat)
	until := now.Add(p.Lifetime).Format(timeFormat)

	resp := etree.NewElement("saml2p:Response")
	resp.CreateAttr("xmlns:saml2p", nsProtocol)

	response := &Response{el: resp}

	if p.Success && len(p.Attributes) > 0 {
		// Only declared when an attribute value is typed xsd:string.
		resp.CreateAttr("xmlns:"+xsdPrefix, nsXSD)
		response.inclusivePrefixes = xsdPrefix
	}

	setAttr(resp, "Destination", p.ServiceURL)
	resp.CreateAttr(idAttribute, randomID())
	setAttr(resp, "InResponseTo", p.RequestID)
	resp.CreateAttr("IssueInstant", instant)
	resp.CreateAttr("Version", "2.0")

	issuer := resp.CreateElement("saml2:Issuer")
	issuer.CreateAttr("xmlns:saml2", nsAssertion)
	issuer.SetText(idp.entityID)

	status := resp.CreateElement("saml2p:Status")
	code := status.CreateElement("saml2p:StatusCode")

	if !p.Success {
		code.CreateAttr("Value", statusResponder)
		code.CreateElement("saml2p:StatusCode").CreateAttr("Value", statusAuthnFailed)

		message := status.CreateElement("saml2p:StatusMessage")
		if p.StatusMessage != "" {
			message.SetText(p.StatusMessage)
		}

		return response
	}

	code.CreateAttr("Value", statusSuccess)

	assertion := resp.CreateElement("saml2:Assertion")
	assertion.CreateAttr("xmlns:saml2", nsAssertion)
	assertion.CreateAttr(idAttribute, assertionID(p.SessionToken))
	assertion.CreateAttr("IssueInstant", instant)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateElement("saml2:Issuer").SetText(idp.entityID)

	names := sortedKeys(p.Attributes)

	subject := assertion.CreateElement("saml2:Subject")

	if len(names) > 0 {
		// The NameID is the value of the first attribute, by identifier.
		nameID := subject.CreateElement("saml2:NameID")
		nameID.CreateAttr("Format", nameIDTransient)
		nameID.SetText(p.Attributes[names[0]])
	}

	confirmation := subject.CreateElement("saml2:SubjectConfirmation")
	confirmation.CreateAttr("Method", confirmationBearer)

	data := confirmation.CreateElement("saml2:SubjectConfirmationData")
	setAttr(data, "InResponseTo", p.RequestID)
	data.CreateAttr("NotOnOrAfter", until)
	setAttr(data, "Recipient", p.ServiceURL)

	conditions := assertion.CreateElement("saml2:Conditions")
	conditions.CreateAttr("NotBefore", instant)
	conditions.CreateAttr("NotOnOrAfter", until)
	conditions.CreateElement("saml2:AudienceRestriction").CreateElement("saml2:Audience").SetText(p.Audience)

	statement := assertion.CreateElement("saml2:AttributeStatement")

	for _, name := range names {
		attribute := statement.CreateElement("saml2:Attribute")
		attribute.CreateAttr("Name", name)

		value := attribute.CreateElement("saml2:AttributeValue")
		value.CreateAttr("xmlns:xsi", nsXSI)
		value.CreateAttr("xsi:type", xsdPrefix+":string")
		value.SetText(p.Attributes[name])
	}

	authn := assertion.CreateElement("saml2:AuthnStatement")
	authn.CreateAttr("AuthnInstant", instant)
	authn.CreateElement("saml2:AuthnContext").CreateElement("saml2:AuthnContextClassRef").SetText(authnContextClass)

	return response
}

// Sign adds an enveloped XML signature over the whole Response, the one
// OpenSAML made: RSA with SHA-256, a SHA-256 digest, exclusive
// canonicalization and the certificate in KeyInfo. The assertion has no
// signature of its own; it is covered by this one, as it was in the Java
// service.
//
// The signature is not made here. The Response gets a Signature element
// without values, and signedxml computes the digest and the signature that
// the element describes.
func (idp *IdentityProvider) Sign(r *Response) error {
	if r.signed {
		return errors.New("the Response is already signed")
	}

	id, _ := attr(r.el, idAttribute)
	template := idp.signatureTemplate(id, r.inclusivePrefixes)

	// The schema wants the Signature right after the Issuer.
	r.el.InsertChildAt(1, template)

	doc := etree.NewDocument()
	doc.WriteSettings = canonicalWriteSettings
	doc.SetRoot(r.el)

	signer, err := signedxml.NewSignerFromDoc(doc)
	if err == nil {
		signer.SetReferenceIDAttribute(idAttribute)
		_, err = signer.Sign(idp.key)
	}

	if err != nil {
		r.el.RemoveChild(template)

		return err
	}

	// signedxml declares the ds prefix on SignedInfo a second time. The
	// declaration on Signature is in scope there, so the copy says nothing
	// and OpenSAML did not write it.
	if info := child(template, nsDSig, "SignedInfo"); info != nil {
		info.RemoveAttr("xmlns:ds")
	}

	// OpenSAML wrapped the signature value in lines of 76 characters. It is
	// not part of what is signed, and base64 decoders skip the line breaks.
	if value := child(template, nsDSig, "SignatureValue"); value != nil {
		value.SetText(wrapBase64(value.Text()))
	}

	r.signed = true

	return nil
}

// wrapBase64 breaks base64 text into lines of 76 characters, the way
// OpenSAML wrote a SignatureValue: CRLF between lines, LF around them.
func wrapBase64(text string) string {
	const width = 76

	var lines []string
	for len(text) > width {
		lines = append(lines, text[:width])
		text = text[width:]
	}

	lines = append(lines, text)

	return "\n" + strings.Join(lines, "\r\n") + "\n"
}

// signatureTemplate returns the Signature element for the element with the
// given ID, with an empty DigestValue and SignatureValue.
//
// A prefix that is only used inside a value, as xsd is in
// xsi:type="xsd:string", is not visibly used, and exclusive canonicalization
// would leave its declaration out of what is signed. Listing it as an
// InclusiveNamespaces prefix keeps the declaration in, so that the signed
// bytes can be read on their own. OpenSAML did the same.
func (idp *IdentityProvider) signatureTemplate(id, inclusivePrefixes string) *etree.Element {
	// The line breaks are those OpenSAML wrote. Those inside SignedInfo are
	// part of what is signed, so with them the signature over a given
	// Response is the one the Java service made, byte for byte.
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", nsDSig)
	sig.CreateText("\n")

	info := sig.CreateElement("ds:SignedInfo")
	info.CreateText("\n")
	info.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", algExclusiveC14N)
	info.CreateText("\n")
	info.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", SigAlgRSASHA256)
	info.CreateText("\n")

	reference := info.CreateElement("ds:Reference")
	reference.CreateAttr("URI", "#"+id)
	reference.CreateText("\n")
	info.CreateText("\n")

	transforms := reference.CreateElement("ds:Transforms")
	transforms.CreateText("\n")
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", algEnveloped)
	transforms.CreateText("\n")

	canonicalize := transforms.CreateElement("ds:Transform")
	canonicalize.CreateAttr("Algorithm", algExclusiveC14N)
	transforms.CreateText("\n")

	if inclusivePrefixes != "" {
		inclusive := canonicalize.CreateElement("ec:InclusiveNamespaces")
		inclusive.CreateAttr("xmlns:ec", algExclusiveC14N)
		inclusive.CreateAttr("PrefixList", inclusivePrefixes)
	}

	reference.CreateText("\n")
	reference.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", algSHA256)
	reference.CreateText("\n")
	reference.CreateElement("ds:DigestValue")
	reference.CreateText("\n")

	sig.CreateText("\n")
	sig.CreateElement("ds:SignatureValue")
	sig.CreateText("\n")
	sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(idp.cert.Raw))

	return sig
}

// XML serializes the Response, with the XML declaration the Java service
// wrote. Text and attribute values are escaped the way canonicalization
// expects, so a carriage return in an attribute value survives the trip to
// the service provider and the digest still matches.
func (r *Response) XML() ([]byte, error) {
	doc := etree.NewDocument()
	doc.WriteSettings = canonicalWriteSettings
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(r.el.Copy())

	return doc.WriteToBytes()
}

// Verify checks that data is a Response carrying a valid signature made with
// the bridge's own key. The Java service did this to every Response before
// handing it out, and so does the bridge. goxmldsig does the check, which
// shares no canonicalization code with the library that signed. The validity
// period of the certificate is not part of the check: a Response is signed
// whatever the dates in the certificate say, as before.
func (idp *IdentityProvider) Verify(data []byte) error {
	doc, err := parseXML(data, maxMetadataBytes)
	if err != nil {
		return err
	}

	root := doc.Root()
	if !is(root, nsProtocol, "Response") {
		return fmt.Errorf("root element is %s, not a Response", root.FullTag())
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idp.cert},
	})
	ctx.IdAttribute = idAttribute
	ctx.Clock = dsig.NewFakeClockAt(idp.cert.NotBefore)

	if _, err := ctx.Validate(root); err != nil {
		return err
	}

	return nil
}

// canonicalWriteSettings escape text and attribute values the way
// canonicalization does. With etree's defaults a carriage return is written
// as it is, the parser on the other side turns it into a line feed, and the
// digest no longer matches.
var canonicalWriteSettings = etree.WriteSettings{CanonicalText: true, CanonicalAttrVal: true}

func setAttr(el *etree.Element, name, value string) {
	if value != "" {
		el.CreateAttr(name, value)
	}
}

// randomID returns an identifier that is a valid xs:ID: an underscore and
// 160 random bits in hexadecimal.
func randomID() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on the platforms Go supports.
		panic(err)
	}

	return "_" + strings.ToUpper(hex.EncodeToString(b))
}

// assertionID wraps the IRMA session token as a valid xs:ID. A token may
// start with a digit, which an ID may not.
func assertionID(token string) string {
	if token == "" {
		return randomID()
	}

	return "_" + strings.ToUpper(hex.EncodeToString([]byte(token)))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
