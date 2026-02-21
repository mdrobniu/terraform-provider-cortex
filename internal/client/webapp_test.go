package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebappClient_DoRequest_SetsHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "XMLHttpRequest", r.Header.Get("X-Requested-With"))
		assert.NotEmpty(t, r.Header.Get("X-XDR-REQUEST-TOKEN"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
	}
	_, _, err := wc.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
}

func TestWebappClient_DoRequest_SetsCSRFToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-csrf-token", r.Header.Get("X-CSRF-TOKEN"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
		csrfToken:  "my-csrf-token",
	}
	_, _, err := wc.DoRequest(context.Background(), "POST", "/test", map[string]string{"key": "val"})
	assert.NoError(t, err)
}

func TestWebappClient_DoRequest_SetsXSRFToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-xsrf-token", r.Header.Get("X-XSRF-TOKEN"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
		xsrfToken:  "my-xsrf-token",
	}
	_, _, err := wc.DoRequest(context.Background(), "POST", "/test", nil)
	assert.NoError(t, err)
}

func TestWebappClient_DoRequest_RedirectReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login/sso")
		w.WriteHeader(302)
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
	}
	// Need to disable redirect following on the test client too
	wc.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	_, status, err := wc.DoRequest(context.Background(), "GET", "/api/webapp/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 302, status)
	assert.True(t, IsRedirect(err))
	assert.Contains(t, err.Error(), "session may be expired")
}

func TestWebappClient_DoRequest_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`forbidden`))
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
	}
	_, status, err := wc.DoRequest(context.Background(), "POST", "/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 403, status)
}

func TestWebappClient_DoRequest_SendsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "value", body["key"])
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	wc := &WebappClient{
		UIURL:      srv.URL,
		HTTPClient: srv.Client(),
	}
	_, _, err := wc.DoRequest(context.Background(), "POST", "/test", map[string]string{"key": "value"})
	assert.NoError(t, err)
}

func TestNewWebappClientFromToken_SetsCookies(t *testing.T) {
	wc, err := NewWebappClientFromToken("https://xsiam.example.com", "my-session-token", true)
	require.NoError(t, err)
	assert.Equal(t, "https://xsiam.example.com", wc.UIURL)
	// Verify the HTTPClient has a cookie jar with the session cookies
	assert.NotNil(t, wc.HTTPClient.Jar)
}
