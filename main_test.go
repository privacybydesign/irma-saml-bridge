package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runMainEnv makes the test binary run main instead of the tests, so that
// TestLogsGoToStandardOutput can look at what the service writes.
const runMainEnv = "IRMA_SAML_BRIDGE_RUN_MAIN"

// The service logs to standard output as log/slog text, as the README says.
// The default handler of log/slog would write to standard error.
func TestLogsGoToStandardOutput(t *testing.T) {
	if os.Getenv(runMainEnv) == "1" {
		main()

		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLogsGoToStandardOutput$") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(),
		runMainEnv+"=1",
		"CONFIG_PATH="+filepath.Join(t.TempDir(), "missing.json"))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "main must exit when the configuration is missing")
	assert.Equal(t, 1, exitErr.ExitCode())

	assert.Contains(t, stdout.String(), `level=ERROR msg="irma-saml-bridge stopped" error=`)
	assert.Contains(t, stdout.String(), "missing.json")
	assert.NotContains(t, stderr.String(), "irma-saml-bridge stopped")
}

// A request that is being answered when SIGTERM comes still gets its
// answer, and serve returns only after that.
func TestServeDrainsRequestsInFlight(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("answered"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	served := make(chan error, 1)

	go func() { served <- serve(ctx, newHTTPServer(handler), ln) }()

	type result struct {
		body string
		err  error
	}

	answered := make(chan result, 1)

	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/") //nolint:noctx // a test
		if err != nil {
			answered <- result{err: err}

			return
		}

		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		answered <- result{body: string(body), err: err}
	}()

	<-entered
	stop()

	select {
	case err := <-served:
		t.Fatalf("serve returned while a request was in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	got := <-answered
	require.NoError(t, got.err)
	assert.Equal(t, "answered", got.body)

	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the request was answered")
	}

	// New connections are refused once shutdown has started.
	_, err = net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.Error(t, err)
}

func TestServeReturnsWhenServingFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	err = serve(context.Background(), newHTTPServer(http.NotFoundHandler()), ln)
	require.Error(t, err)
	assert.False(t, errors.Is(err, http.ErrServerClosed))
}

func TestServeStopsWhenIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, stop := context.WithCancel(context.Background())
	stop()

	require.NoError(t, serve(ctx, newHTTPServer(http.NotFoundHandler()), ln))
}
