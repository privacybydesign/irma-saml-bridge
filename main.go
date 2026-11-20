// Command irma-saml-bridge is a SAML 2.0 identity provider that lets a user
// log in by disclosing attributes with the Yivi app. It sits between a SAML
// broker and an IRMA server: an AuthnRequest comes in, an IRMA disclosure
// session is run, and a signed Response goes back.
package main

import (
	"context"
	"errors"
	"log/slog"
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

	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-stop.Done()

		ctx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelShutdown()

		_ = httpServer.Shutdown(ctx)
	}()

	slog.Info("listening",
		"addr", cfg.listenAddr,
		"context_path", cfg.contextPath,
		"entity_id", cfg.issuerName(),
		"sso_url", cfg.constructURL("/request"),
		"service_providers", srv.registry.Len())

	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
