package irma

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func irmaServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv.URL
}

func startSession(t *testing.T, baseURL string) (string, *Error) {
	t.Helper()

	data, err := NewClient(false).StartSession(context.Background(), baseURL, "accessToken")
	if err == nil {
		return data, nil
	}

	var irmaErr *Error
	require.ErrorAs(t, err, &irmaErr)

	return "", irmaErr
}

// Counterpart of IrmaServiceTest.startSessionTest.
func TestStartSession(t *testing.T) {
	var (
		gotPath, gotMethod, gotContentType string
		gotBody                            []byte
	)

	url := irmaServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotContentType = r.URL.Path, r.Method, r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"token":"t","sessionPtr":{"u":"x","irmaqr":"disclosing"}}`))
	})

	data, irmaErr := startSession(t, url+"/irma")
	require.Nil(t, irmaErr)

	// The session data is handed on untouched.
	assert.Equal(t, `{"token":"t","sessionPtr":{"u":"x","irmaqr":"disclosing"}}`, data)
	assert.Equal(t, "/irma/session", gotPath)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "text/plain", gotContentType)
	assert.Equal(t, "accessToken", string(gotBody))
}

// Counterpart of IrmaServiceTest.startSessionTestNoResponseBody.
func TestStartSessionNoResponseBody(t *testing.T) {
	url := irmaServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	data, irmaErr := startSession(t, url)
	require.Nil(t, irmaErr)
	assert.Empty(t, data)
}

// Counterpart of IrmaServiceTest.startSessionTestWithStatusCodeIsNot2xx.
func TestStartSessionRedirectIsNotFollowed(t *testing.T) {
	followed := false

	url := irmaServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true

			return
		}

		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})

	_, irmaErr := startSession(t, url)
	require.NotNil(t, irmaErr)
	assert.Equal(t, http.StatusInternalServerError, irmaErr.Status)
	assert.Equal(t, "Start session was not successful", irmaErr.Message)
	assert.False(t, followed)
}

// Counterpart of IrmaServiceTest.startSessionTestWithException.
func TestStartSessionServerError(t *testing.T) {
	url := irmaServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "database password is hunter2", http.StatusBadGateway)
	})

	_, irmaErr := startSession(t, url)
	require.NotNil(t, irmaErr)
	assert.Equal(t, http.StatusInternalServerError, irmaErr.Status)

	// What a failing IRMA server says does not reach the user.
	assert.Equal(t, "Something went wrong when trying to connect with the IRMA server", irmaErr.Message)
}

func TestStartSessionUnreachable(t *testing.T) {
	url := irmaServer(t, func(http.ResponseWriter, *http.Request) {})

	// A port nothing listens on.
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	_, irmaErr := startSession(t, closed.URL)
	require.NotNil(t, irmaErr)
	assert.Equal(t, http.StatusInternalServerError, irmaErr.Status)
	assert.Equal(t, "Something went wrong when trying to connect with the IRMA server", irmaErr.Message)

	_, err := NewClient(false).StartSession(context.Background(), "://not a url", "t")
	require.Error(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = NewClient(false).StartSession(ctx, url, "t")
	require.Error(t, err)
}

// Counterpart of IrmaServiceTest.startSessionTestWithHttpClientErrorException:
// what the IRMA server answers to a request it refuses is passed on, with
// its status.
func TestStartSessionClientError(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
		want   string
	}{
		"with body":    {http.StatusBadRequest, `{"error":"INVALID_REQUEST"}`, `400 Bad Request: "{"error":"INVALID_REQUEST"}"`},
		"without body": {http.StatusForbidden, ``, `403 Forbidden: [no body]`},
		"line breaks":  {http.StatusUnauthorized, "a\r\nb\nc", `401 Unauthorized: "a<EOL>b<LF>c"`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			url := irmaServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})

			_, irmaErr := startSession(t, url)
			require.NotNil(t, irmaErr)
			assert.Equal(t, tt.status, irmaErr.Status)
			assert.Equal(t, tt.want, irmaErr.Message)
			assert.Equal(t, tt.want, irmaErr.Error())
		})
	}
}

// The Java service accepted any certificate from the IRMA server. The
// bridge checks it, unless told not to.
func TestStartSessionVerifiesServerCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient(false).StartSession(context.Background(), srv.URL, "t")

	var irmaErr *Error
	require.ErrorAs(t, err, &irmaErr)
	assert.Equal(t, http.StatusInternalServerError, irmaErr.Status)

	data, err := NewClient(true).StartSession(context.Background(), srv.URL, "t")
	require.NoError(t, err)
	assert.Equal(t, `{}`, data)

	// Verification is on by default and TLS 1.2 is the oldest version.
	config := NewClient(false).http.Transport.(*http.Transport).TLSClientConfig
	assert.False(t, config.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
}

func TestErrorIsAnError(t *testing.T) {
	var err error = &Error{Status: 400, Message: "m"}

	var target *Error
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "m", err.Error())
}
