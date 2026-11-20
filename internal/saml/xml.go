// Package saml holds the SAML 2.0 identity provider side of the bridge: the
// service provider metadata, decoding and verifying an AuthnRequest received
// with the HTTP-Redirect binding, and building and signing the Response.
//
// It mirrors what the Java service did with OpenSAML. XML signatures are made
// and checked by goxmldsig; nothing in here implements XML-DSig itself.
package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsReqAttr   = "urn:oasis:names:tc:SAML:protocol:ext:req-attr"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsXSD       = "http://www.w3.org/2001/XMLSchema"
	nsXSI       = "http://www.w3.org/2001/XMLSchema-instance"
	nsXML       = "http://www.w3.org/XML/1998/namespace"

	// BindingRedirect is the only binding the bridge receives requests with.
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	// MaxRequestXMLBytes bounds an inflated AuthnRequest. Real requests are a
	// few kilobytes; the bound stops a DEFLATE bomb.
	MaxRequestXMLBytes = 128 << 10

	// maxMetadataBytes bounds one metadata file.
	maxMetadataBytes = 8 << 20

	maxXMLDepth  = 64
	maxXMLTokens = 200_000
)

// ErrXML is returned for XML the bridge refuses to read: too large, too deep,
// not well formed, or carrying a DTD.
var ErrXML = errors.New("saml: refused XML")

// parseXML reads data into a document after checking that it is safe to do
// so. A document type declaration is refused, so there are no entity
// declarations to expand and nothing external to fetch. The decoder is
// strict: a reference to an entity other than the five predefined ones is an
// error.
func parseXML(data []byte, maxBytes int) (*etree.Document, error) {
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes is more than the %d allowed", ErrXML, len(data), maxBytes)
	}

	if err := checkXMLTokens(data); err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrXML, err)
	}

	if doc.Root() == nil {
		return nil, fmt.Errorf("%w: no root element", ErrXML)
	}

	return doc, nil
}

// checkXMLTokens walks the tokens of data once, before anything is built
// from it.
func checkXMLTokens(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true

	depth, tokens, roots := 0, 0, 0

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("%w: %w", ErrXML, err)
		}

		tokens++
		if tokens > maxXMLTokens {
			return fmt.Errorf("%w: more than %d tokens", ErrXML, maxXMLTokens)
		}

		switch t := tok.(type) {
		case xml.Directive:
			return fmt.Errorf("%w: document type declarations are not allowed", ErrXML)
		case xml.ProcInst:
			if t.Target != "xml" || depth != 0 || roots != 0 {
				return fmt.Errorf("%w: processing instruction %q is not allowed", ErrXML, t.Target)
			}
		case xml.StartElement:
			if depth == 0 {
				roots++
			}

			depth++
			if depth > maxXMLDepth {
				return fmt.Errorf("%w: nested deeper than %d elements", ErrXML, maxXMLDepth)
			}
		case xml.EndElement:
			depth--
		}
	}

	if roots != 1 {
		return fmt.Errorf("%w: expected one root element, found %d", ErrXML, roots)
	}

	return nil
}

// is reports whether el is the element local in namespace ns.
func is(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && el.NamespaceURI() == ns
}

// child returns the first child element local in namespace ns, or nil.
func child(el *etree.Element, ns, local string) *etree.Element {
	for _, c := range el.ChildElements() {
		if is(c, ns, local) {
			return c
		}
	}

	return nil
}

// children returns the child elements local in namespace ns.
func children(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element

	for _, c := range el.ChildElements() {
		if is(c, ns, local) {
			out = append(out, c)
		}
	}

	return out
}

// attr returns the value of the attribute name that is in no namespace, and
// whether el has it.
func attr(el *etree.Element, name string) (string, bool) {
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value, true
		}
	}

	return "", false
}

// attrNS returns the value of the attribute local in namespace ns.
func attrNS(el *etree.Element, ns, local string) (string, bool) {
	for i := range el.Attr {
		a := &el.Attr[i]
		if a.Space == "" || a.Space == "xmlns" || a.Key != local {
			continue
		}

		if a.NamespaceURI() == ns {
			return a.Value, true
		}
	}

	return "", false
}

// resolvePrefix returns the namespace bound to prefix where el stands.
func resolvePrefix(el *etree.Element, prefix string) string {
	if prefix == "xml" {
		return nsXML
	}

	for e := el; e != nil; e = e.Parent() {
		for _, a := range e.Attr {
			if prefix == "" && a.Space == "" && a.Key == "xmlns" {
				return a.Value
			}

			if prefix != "" && a.Space == "xmlns" && a.Key == prefix {
				return a.Value
			}
		}
	}

	return ""
}

// isXSDString reports whether el is typed xsi:type="xs:string", whatever
// prefix the document uses for XML Schema.
func isXSDString(el *etree.Element) bool {
	value, ok := attrNS(el, nsXSI, "type")
	if !ok {
		return false
	}

	prefix, local, found := strings.Cut(strings.TrimSpace(value), ":")
	if !found {
		prefix, local = "", prefix
	}

	return local == "string" && resolvePrefix(el, prefix) == nsXSD
}
