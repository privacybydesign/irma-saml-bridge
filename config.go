package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	envConfigPath  = "CONFIG_PATH"
	envContextPath = "SERVER_SERVLET_CONTEXT_PATH"
	envPort        = "SERVER_PORT"

	defaultConfigPath  = "./config.json"
	defaultContextPath = "/irma-saml-bridge"
	defaultPort        = "8080"

	defaultTTLSeconds = 360
)

// irmaPath says where the IRMA server for a service provider is.
type irmaPath struct {
	// Host is the host the browser and the Yivi app reach the IRMA server
	// on. It is shown to the user in the app.
	Host string `json:"host"`

	// IrmaServiceHost is the host the bridge itself starts the session on.
	IrmaServiceHost string `json:"irmaServiceHost"`

	// Postfix is the path after the host, for example "/irma".
	Postfix string `json:"postfix"`
}

// config is config.json. The keys are those of the Java service.
type config struct {
	Host    string `json:"host"`
	Postfix string `json:"postfix"`

	// IssuerName is the entity ID of the identity provider. Without it the
	// host is used.
	IssuerName *string `json:"issuerName"`

	JWTPrivateKeyPath      string  `json:"jwtPrivateKeyPath"`
	TestIrmaPrivateKeyPath *string `json:"testIrmaPrivateKeyPath"`
	IrmaPublicKeyPath      string  `json:"irmaPublicKeyPath"`
	SAMLCertificatePath    string  `json:"samlCertificatePath"`
	SAMLPrivateKeyPath     string  `json:"samlPrivateKeyPath"`
	SAMLMetadataPath       string  `json:"samlMetadataPath"`

	DefaultCondiscon [][][]string        `json:"defaultCondiscon"`
	DefaultMap       *irmaPath           `json:"defaultMap"`
	IrmaMapping      map[string]irmaPath `json:"irmaMapping"`

	HTTPSUsed        *bool `json:"httpsUsed"`
	RequestTTLInSec  *int  `json:"requestTtlInSec"`
	ResponseTTLInSec *int  `json:"responseTtlInSec"`

	// IrmaServerTLSInsecureSkipVerify turns off certificate verification
	// for the call to the IRMA server. It is not a key of the Java service,
	// which never verified that certificate. Leave it out.
	IrmaServerTLSInsecureSkipVerify bool `json:"irmaServerTlsInsecureSkipVerify"`

	// contextPath is the path the service is served under. It comes from
	// SERVER_SERVLET_CONTEXT_PATH, not from the file.
	contextPath string

	// listenAddr is ":8080" unless SERVER_PORT says otherwise.
	listenAddr string
}

var contextPathPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*$`)

// loadConfig reads the configuration file named by CONFIG_PATH, or
// ./config.json, and the context path from SERVER_SERVLET_CONTEXT_PATH.
func loadConfig(getenv func(string) string) (*config, error) {
	path := getenv(envConfigPath)
	if path == "" {
		path = defaultConfigPath
	}

	data, err := os.ReadFile(path) //nolint:gosec // the operator chooses the file
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}

	cfg := &config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}

	cfg.contextPath, err = contextPath(getenv(envContextPath))
	if err != nil {
		return nil, err
	}

	cfg.listenAddr, err = listenAddr(getenv(envPort))
	if err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}

	return cfg, nil
}

// contextPath normalizes the value of SERVER_SERVLET_CONTEXT_PATH. Spring
// Boot read that variable for its server.servlet.context-path.
func contextPath(value string) (string, error) {
	if value == "" {
		return defaultContextPath, nil
	}

	value = strings.TrimRight(value, "/")
	if !contextPathPattern.MatchString(value) {
		return "", fmt.Errorf("%s %q is not a path like /saml-bridge", envContextPath, value)
	}

	return value, nil
}

// listenAddr returns the address to listen on. Spring Boot read the port
// from SERVER_PORT, and 8080 was its default.
func listenAddr(port string) (string, error) {
	if port == "" {
		port = defaultPort
	}

	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%s %q is not a port number", envPort, port)
	}

	return ":" + port, nil
}

func (c *config) validate() error {
	var missing []string

	for name, value := range map[string]string{
		"host":                c.Host,
		"jwtPrivateKeyPath":   c.JWTPrivateKeyPath,
		"irmaPublicKeyPath":   c.IrmaPublicKeyPath,
		"samlCertificatePath": c.SAMLCertificatePath,
		"samlPrivateKeyPath":  c.SAMLPrivateKeyPath,
		"samlMetadataPath":    c.SAMLMetadataPath,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}

	if c.DefaultCondiscon == nil {
		missing = append(missing, "defaultCondiscon")
	}

	if c.DefaultMap == nil {
		missing = append(missing, "defaultMap")
	}

	if len(missing) > 0 {
		return errors.New("missing " + strings.Join(sortedStrings(missing), ", "))
	}

	if c.requestTTL() <= 0 || c.responseTTL() <= 0 {
		return errors.New("requestTtlInSec and responseTtlInSec must be positive")
	}

	return nil
}

// issuerName is the entity ID of the identity provider.
func (c *config) issuerName() string {
	if c.IssuerName == nil {
		return c.Host
	}

	return *c.IssuerName
}

// protocol is "https://" unless httpsUsed is false. It is used for the
// bridge's own URLs and for both URLs of the IRMA server.
func (c *config) protocol() string {
	if c.HTTPSUsed != nil && !*c.HTTPSUsed {
		return "http://"
	}

	return "https://"
}

// constructURL returns the public URL of a path of the bridge.
func (c *config) constructURL(path string) string {
	return c.protocol() + c.Host + c.Postfix + path
}

func (c *config) requestTTL() time.Duration {
	return seconds(c.RequestTTLInSec)
}

func (c *config) responseTTL() time.Duration {
	return seconds(c.ResponseTTLInSec)
}

func seconds(v *int) time.Duration {
	if v == nil {
		return defaultTTLSeconds * time.Second
	}

	return time.Duration(*v) * time.Second
}

// irmaPathFor returns the IRMA server for the service provider name, with
// {spName} filled in. A name without an entry in irmaMapping gets
// defaultMap.
func (c *config) irmaPathFor(spName string) irmaPath {
	path, ok := c.IrmaMapping[spName]
	if !ok {
		path = *c.DefaultMap
	}

	path.Host = strings.ReplaceAll(path.Host, "{spName}", spName)
	path.Postfix = strings.ReplaceAll(path.Postfix, "{spName}", spName)

	return path
}
