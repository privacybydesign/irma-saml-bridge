package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
