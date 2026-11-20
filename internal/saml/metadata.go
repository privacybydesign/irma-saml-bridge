package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Endpoint is an AssertionConsumerService from a service provider's metadata.
type Endpoint struct {
	Binding  string
	Location string
}

// ServiceProvider is what the bridge keeps of one EntityDescriptor: the keys
// its requests are verified with and the places a Response may be sent to.
type ServiceProvider struct {
	EntityID string

	// SigningKeys come from the KeyDescriptors of the SPSSODescriptor whose
	// use is "signing" or left out. The validity period of a certificate is
	// not checked: the key is trusted because it is in the metadata, as with
	// OpenSAML's explicit key trust engine.
	SigningKeys []*rsa.PublicKey

	// ACS lists the AssertionConsumerServices in document order.
	ACS []Endpoint

	// validUntil is the earliest validUntil that applies, or zero.
	validUntil time.Time

	// source is the file the descriptor was read from, for log lines.
	source string
}

// RedirectACS returns the Location of the first AssertionConsumerService
// with the HTTP-Redirect binding, or "". It is the default the Java service
// used for a request that names no AssertionConsumerServiceURL.
func (sp *ServiceProvider) RedirectACS() string {
	for _, e := range sp.ACS {
		if e.Binding == BindingRedirect {
			return e.Location
		}
	}

	return ""
}

// HasACS reports whether url is the Location of one of the service
// provider's AssertionConsumerServices, whatever its binding. The match is
// exact: SAML core §3.4.1 asks the identity provider to check the URL
// against the metadata before sending a Response to it.
func (sp *ServiceProvider) HasACS(url string) bool {
	if url == "" {
		return false
	}

	for _, e := range sp.ACS {
		if e.Location == url {
			return true
		}
	}

	return false
}

// Registry holds the service providers that may use the bridge.
type Registry struct {
	byID map[string]*ServiceProvider
}

// NewRegistry returns a registry of the given service providers. When two
// have the same entity ID the first one is kept.
func NewRegistry(sps ...*ServiceProvider) *Registry {
	r := &Registry{byID: map[string]*ServiceProvider{}}

	for _, sp := range sps {
		if prev, dup := r.byID[sp.EntityID]; dup {
			slog.Warn("duplicate entityID in metadata, keeping the first",
				"entity_id", sp.EntityID, "kept", prev.source, "ignored", sp.source)

			continue
		}

		r.byID[sp.EntityID] = sp
	}

	return r
}

// LoadRegistry reads every metadata file in dir. Each file holds one
// EntityDescriptor or an EntitiesDescriptor. Directories and files whose
// name starts with a dot are skipped; a file that cannot be read stops the
// service from starting.
func LoadRegistry(dir string) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("metadata directory: %w", err)
	}

	names := make([]string, 0, len(entries))

	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}

		// A config map mounts its files as symbolic links, so look at
		// what the name points to.
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("metadata file %s: %w", e.Name(), err)
		}

		if info.Mode().IsRegular() {
			names = append(names, e.Name())
		}
	}

	sort.Strings(names)

	var sps []*ServiceProvider

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory comes from the configuration
		if err != nil {
			return nil, fmt.Errorf("metadata file %s: %w", name, err)
		}

		found, err := ParseMetadata(data)
		if err != nil {
			return nil, fmt.Errorf("metadata file %s: %w", name, err)
		}

		for _, sp := range found {
			sp.source = name

			if len(sp.SigningKeys) == 0 {
				slog.Warn("metadata has no RSA signing certificate, its requests cannot be verified",
					"entity_id", sp.EntityID, "file", name)
			}
		}

		sps = append(sps, found...)
	}

	return NewRegistry(sps...), nil
}

// Len returns the number of service providers.
func (r *Registry) Len() int { return len(r.byID) }

// Lookup returns the service provider with the given entity ID. Metadata
// past its validUntil is not returned.
func (r *Registry) Lookup(entityID string, now time.Time) (*ServiceProvider, bool) {
	sp, ok := r.byID[entityID]
	if !ok {
		return nil, false
	}

	if !sp.validUntil.IsZero() && !now.Before(sp.validUntil) {
		return nil, false
	}

	return sp, true
}

// ParseMetadata reads the service providers out of a metadata document.
func ParseMetadata(data []byte) ([]*ServiceProvider, error) {
	doc, err := parseXML(data, maxMetadataBytes)
	if err != nil {
		return nil, err
	}

	var sps []*ServiceProvider
	if err := collectEntities(doc.Root(), time.Time{}, &sps, 0); err != nil {
		return nil, err
	}

	if len(sps) == 0 {
		return nil, errors.New("no EntityDescriptor found")
	}

	return sps, nil
}

func collectEntities(el *etree.Element, validUntil time.Time, out *[]*ServiceProvider, depth int) error {
	if until, ok := attr(el, "validUntil"); ok {
		t, err := parseTime(until)
		if err != nil {
			return fmt.Errorf("validUntil %q: %w", until, err)
		}

		if validUntil.IsZero() || t.Before(validUntil) {
			validUntil = t
		}
	}

	switch {
	case is(el, nsMetadata, "EntitiesDescriptor"):
		for _, c := range el.ChildElements() {
			if !is(c, nsMetadata, "EntityDescriptor") && !is(c, nsMetadata, "EntitiesDescriptor") {
				continue
			}

			if err := collectEntities(c, validUntil, out, depth+1); err != nil {
				return err
			}
		}

		return nil

	case is(el, nsMetadata, "EntityDescriptor"):
		sp, err := parseEntity(el, validUntil)
		if err != nil {
			return err
		}

		*out = append(*out, sp)

		return nil

	case depth == 0:
		return fmt.Errorf("root element is %s, not an EntityDescriptor or EntitiesDescriptor", el.FullTag())
	}

	return nil
}

func parseEntity(el *etree.Element, validUntil time.Time) (*ServiceProvider, error) {
	entityID, _ := attr(el, "entityID")
	if entityID == "" {
		return nil, errors.New("EntityDescriptor has no entityID")
	}

	sp := &ServiceProvider{EntityID: entityID, validUntil: validUntil}

	// The endpoints come from the first SPSSODescriptor for SAML 2.0, the
	// keys from all of them, as OpenSAML resolved them.
	first := true

	for _, role := range children(el, nsMetadata, "SPSSODescriptor") {
		protocols, _ := attr(role, "protocolSupportEnumeration")
		if !supportsSAML2(protocols) {
			continue
		}

		keys, err := signingKeys(role)
		if err != nil {
			return nil, fmt.Errorf("entity %s: %w", entityID, err)
		}

		sp.SigningKeys = append(sp.SigningKeys, keys...)

		if !first {
			continue
		}

		first = false

		for _, acs := range children(role, nsMetadata, "AssertionConsumerService") {
			binding, _ := attr(acs, "Binding")
			location, _ := attr(acs, "Location")
			sp.ACS = append(sp.ACS, Endpoint{Binding: binding, Location: location})
		}
	}

	return sp, nil
}

func supportsSAML2(protocols string) bool {
	return slices.Contains(strings.Fields(protocols), nsProtocol)
}

// signingKeys returns the RSA keys of the certificates a role lists for
// signing. Per X509Data the first certificate is taken, which is the end
// entity certificate by XML-DSig convention.
func signingKeys(role *etree.Element) ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey

	for _, kd := range children(role, nsMetadata, "KeyDescriptor") {
		if use, ok := attr(kd, "use"); ok && use != "signing" {
			continue
		}

		keyInfo := child(kd, nsDSig, "KeyInfo")
		if keyInfo == nil {
			continue
		}

		for _, data := range children(keyInfo, nsDSig, "X509Data") {
			certEl := child(data, nsDSig, "X509Certificate")
			if certEl == nil {
				continue
			}

			cert, err := parseBase64Certificate(certEl.Text())
			if err != nil {
				return nil, fmt.Errorf("signing certificate: %w", err)
			}

			key, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				slog.Warn("skipping a signing certificate that is not RSA", "subject", cert.Subject.String())

				continue
			}

			keys = append(keys, key)
		}
	}

	return keys, nil
}

func parseBase64Certificate(text string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(stripSpace(text))
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// stripSpace removes the white space that metadata wraps base64 in.
func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}

		return r
	}, s)
}

// parseTime reads an xs:dateTime with a time zone.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
}
