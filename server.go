package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/privacybydesign/irma-saml-bridge/internal/irma"
	"github.com/privacybydesign/irma-saml-bridge/internal/replay"
	"github.com/privacybydesign/irma-saml-bridge/internal/saml"
)

// The page with the QR code. Its script and style sheet are built from
// assets/ by the node stage of the Dockerfile and copied to static/assets,
// which is empty in the repository apart from a placeholder.
//
//go:embed templates/irma-request.html
var pageTemplate string

//go:embed all:static
var staticFS embed.FS

const (
	headerContentType = "Content-Type"
	contentTypeHTML   = "text/html;charset=UTF-8"
	contentTypeJSON   = "application/json"
	contentTypeText   = "text/plain;charset=UTF-8"

	// The Java service sent its metadata without a Content-Type.
	contentTypeMetadata = "application/samlmetadata+xml"

	// maxAssertBody bounds the JSON posted to /assert and /errorassert: two
	// JWTs, a few kilobytes together.
	maxAssertBody = 256 << 10

	// maxReportBody bounds a client-side error report.
	maxReportBody = 16 << 10
)

// responder makes the SAML Response. It is an interface so that a test can
// make each step fail.
type responder interface {
	NewResponse(p saml.ResponseParams) *saml.Response
	Sign(r *saml.Response) error
	Marshal(r *saml.Response) ([]byte, error)
	Verify(data []byte) error
}

type idpResponder struct{ *saml.IdentityProvider }

func (idpResponder) Marshal(r *saml.Response) ([]byte, error) { return r.XML() }

type server struct {
	cfg      *config
	keys     *keys
	registry *saml.Registry
	idp      *saml.IdentityProvider
	irma     *irma.Client
	answered *replay.Cache
	page     *template.Template
	assets   fs.FS
	now      func() time.Time

	responder responder

	// metadata returns the metadata of the identity provider.
	metadata func() ([]byte, error)
}

func newServer(cfg *config) (*server, error) {
	k, err := loadKeys(cfg)
	if err != nil {
		return nil, err
	}

	registry, err := saml.LoadRegistry(cfg.SAMLMetadataPath)
	if err != nil {
		return nil, err
	}

	idp, err := saml.NewIdentityProvider(cfg.issuerName(), k.samlPrivate, k.samlCertificate)
	if err != nil {
		return nil, err
	}

	page, err := template.New("irma-request").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}

	assets, err := fs.Sub(staticFS, "static/assets")
	if err != nil {
		return nil, err
	}

	s := &server{
		cfg:       cfg,
		keys:      k,
		registry:  registry,
		idp:       idp,
		irma:      irma.NewClient(cfg.IrmaServerTLSInsecureSkipVerify),
		page:      page,
		assets:    assets,
		now:       time.Now,
		responder: idpResponder{idp},
	}
	s.answered = replay.New(func() time.Time { return s.now() }, replay.DefaultCapacity)
	s.metadata = func() ([]byte, error) { return idp.Metadata(cfg.constructURL("/request")) }

	return s, nil
}

// routes maps the endpoints of the Java service, under the context path.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	base := s.cfg.contextPath

	mux.HandleFunc("GET "+base+"/request", s.handleRequest)
	mux.HandleFunc("POST "+base+"/assert", s.handleAssert)
	mux.HandleFunc("POST "+base+"/errorassert", s.handleErrorAssert(nil))
	mux.HandleFunc("POST "+base+"/errorassert/abort", s.handleErrorAssert(userCancelled))
	mux.HandleFunc("POST "+base+"/report", s.handleReport)
	mux.HandleFunc("GET "+base+"/metadata", s.handleMetadata)
	mux.HandleFunc("GET "+base+"/assets/{file}", s.handleAsset)

	mux.HandleFunc("GET "+base+"/actuator/health", handleHealth(`{"status":"UP","groups":["liveness","readiness"]}`))
	mux.HandleFunc("GET "+base+"/actuator/health/liveness", handleHealth(`{"status":"UP"}`))
	mux.HandleFunc("GET "+base+"/actuator/health/readiness", handleHealth(`{"status":"UP"}`))

	mux.HandleFunc("GET "+base+"/test/metadata", s.handleTestMetadata)
	mux.HandleFunc("GET "+base+"/test/request", s.handleTestRequest)
	mux.HandleFunc("POST "+base+"/test/return", handleTestReturn)
	mux.HandleFunc("GET "+base+"/test/assert", s.handleTestAssert)
	mux.HandleFunc("POST "+base+"/test/errorassert", s.handleTestErrorAssert(""))
	mux.HandleFunc("POST "+base+"/test/errorassert/abort", s.handleTestErrorAssert("/abort"))

	return mux
}

// handleHealth answers the probes the way Spring Boot's actuator did. The
// service has no dependency that can be down while it runs, so it is UP once
// it listens.
func handleHealth(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "application/vnd.spring-boot.actuator.v3+json")
		_, _ = w.Write([]byte(body))
	}
}

func (s *server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	data, err := s.metadata()
	if err != nil {
		slog.Error("Failed to write metadata", "action", "metadata-flow", "error", err)
		writeText(w, http.StatusInternalServerError, "Failed to write metadata")

		return
	}

	w.Header().Set(headerContentType, contentTypeMetadata)
	_, _ = w.Write(data)
}

// handleAsset serves the files the node stage built. Nothing else is
// reachable: the name is a single path element, may not start with a dot,
// and must be a regular file.
func (s *server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.HasPrefix(name, ".") || name != path.Base(name) {
		http.NotFound(w, r)

		return
	}

	data, err := fs.ReadFile(s.assets, name)
	if err != nil {
		http.NotFound(w, r)

		return
	}

	// The files are embedded and have no modification time. An ETag lets
	// the browser keep its copy, as Last-Modified did for the Java service.
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", "no-cache")

	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// handleReport logs an error the browser ran into.
func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	var report struct {
		Message string      `json:"message"`
		Source  string      `json:"source"`
		Lineno  json.Number `json:"lineno"`
		Colno   json.Number `json:"colno"`
	}

	if err := decodeJSON(w, r, maxReportBody, &report); err != nil {
		writeText(w, http.StatusBadRequest, "Invalid request body")

		return
	}

	slog.Warn("client side error", "action", "clientsideerror",
		"source", limit(report.Source, 50),
		"linenr", report.Lineno.String(),
		"colnr", report.Colno.String(),
		"message", limit(report.Message, 256))

	w.WriteHeader(http.StatusOK)
}

// limit cuts s to at most n characters.
func limit(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}

	return s
}

// decodeJSON reads a JSON body of at most max bytes into v. Unknown fields
// are ignored, as Jackson was configured to.
func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("request body: %w", err)
	}

	return nil
}

func writeText(w http.ResponseWriter, status int, text string) {
	w.Header().Set(headerContentType, contentTypeText)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("cannot encode response", "error", err)
		writeText(w, http.StatusInternalServerError, "Internal error")

		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
