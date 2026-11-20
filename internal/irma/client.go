// Package irma starts sessions at an IRMA server.
package irma

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// timeout bounds one call to the IRMA server. The page with the QR code
	// waits for it.
	timeout = 30 * time.Second

	// maxBody bounds the session data read from the IRMA server.
	maxBody = 1 << 20

	msgConnect       = "Something went wrong when trying to connect with the IRMA server"
	msgNotSuccessful = "Start session was not successful"
)

// Error is a failure to start a session that can be shown to the user. Status
// is the HTTP status the bridge answers with.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Client talks to IRMA servers.
type Client struct {
	http *http.Client
}

// NewClient returns a client. Server certificates are verified, unlike in
// the Java service, which accepted any certificate. insecureSkipVerify
// brings that back for a deployment that depends on it.
func NewClient(insecureSkipVerify bool) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // opt-in, off by default
	}

	return &Client{http: &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// A redirect is not a started session.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// StartSession posts a signed session request to baseURL + "/session" and
// returns the session data the IRMA server answers with, as it is.
func (c *Client) StartSession(ctx context.Context, baseURL, requestJWT string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/session", strings.NewReader(requestJWT))
	if err != nil {
		slog.Error("cannot build the IRMA session request", "action", "request-flow", "error", err)

		return "", &Error{Status: http.StatusInternalServerError, Message: msgConnect}
	}

	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.http.Do(req) //nolint:gosec // the URL comes from the configuration
	if err != nil {
		slog.Error("cannot reach the IRMA server", "action", "request-flow", "error", err)

		return "", &Error{Status: http.StatusInternalServerError, Message: msgConnect}
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		slog.Error("cannot read the answer of the IRMA server", "action", "request-flow", "error", err)

		return "", &Error{Status: http.StatusInternalServerError, Message: msgConnect}
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return string(body), nil

	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// The IRMA server refused the request. Its answer is passed on, in
		// the wording the Java service used.
		message := clientErrorMessage(resp.StatusCode, body)
		slog.Error("the IRMA server refused the session request",
			"action", "request-flow", "status", resp.StatusCode, "message", message)

		return "", &Error{Status: resp.StatusCode, Message: message}

	case resp.StatusCode >= 500:
		slog.Error("the IRMA server failed", "action", "request-flow", "status", resp.StatusCode)

		return "", &Error{Status: http.StatusInternalServerError, Message: msgConnect}
	}

	slog.Error("the IRMA server did not start a session", "action", "request-flow", "status", resp.StatusCode)

	return "", &Error{Status: http.StatusInternalServerError, Message: msgNotSuccessful}
}

func clientErrorMessage(status int, body []byte) string {
	preface := fmt.Sprintf("%d %s: ", status, http.StatusText(status))
	if len(body) == 0 {
		return preface + "[no body]"
	}

	text := strings.NewReplacer("\r\n", "<EOL>", "\n", "<LF>", "\r", "<CR>").Replace(string(body))

	return preface + `"` + text + `"`
}
