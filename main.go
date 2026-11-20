// Command irma-saml-bridge is a SAML 2.0 identity provider that lets a user
// log in by disclosing attributes with the Yivi app. It sits between a SAML
// broker and an IRMA server: an AuthnRequest comes in, an IRMA disclosure
// session is run, and a signed Response goes back.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second

	// maxHeaderBytes bounds the request line and headers, and with them the
	// AuthnRequest in the query string. Tomcat allowed 8 KiB.
	maxHeaderBytes = 16 << 10
)

func main() {
	if err := run(); err != nil {
		slog.Error("irma-saml-bridge stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}

	srv, err := newServer(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return err
	}

	slog.Info("listening",
		"addr", cfg.listenAddr,
		"context_path", cfg.contextPath,
		"entity_id", cfg.issuerName(),
		"sso_url", cfg.constructURL("/request"),
		"service_providers", srv.registry.Len())

	return serve(ctx, newHTTPServer(srv.routes()), ln)
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// serve answers requests on ln until ctx is done. It then stops taking new
// connections and waits, for at most shutdownTimeout, until the requests in
// flight are answered. Kubernetes sends SIGTERM on every rollout; a login
// that is in /request or /assert at that moment must still get its answer.
func serve(ctx context.Context, httpServer *http.Server, ln net.Listener) error {
	served := make(chan error, 1)

	go func() { served <- httpServer.Serve(ln) }()

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Serve returns as soon as Shutdown starts. Shutdown itself returns once
	// the requests in flight are answered, so that is what is waited for.
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}

	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
