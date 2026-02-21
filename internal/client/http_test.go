package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient creates a Client pointing at the given test server with instant retries.
func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	c, err := NewClient(serverURL, "test-api-key", true)
	require.NoError(t, err)
	c.RetryDelays = []time.Duration{0, 0, 0, 0}
	return c
}

// --- Auth Header Tests ---

func TestDoRequest_SetsAuthorizationHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-api-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.APIKey = "my-api-key"
	_, _, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
}

func TestDoRequest_SetsXDRAuthIDWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "42", r.Header.Get("x-xdr-auth-id"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.AuthID = "42"
	_, _, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
}

func TestDoRequest_OmitsXDRAuthIDWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("x-xdr-auth-id"))
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.AuthID = ""
	_, _, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
}

// --- Request Body Tests ---

func TestDoRequest_SendsJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "hello", body["key"])
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.DoRequest(context.Background(), "POST", "/test", map[string]string{"key": "hello"})
	assert.NoError(t, err)
}

func TestDoRequest_NilBodySendsNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, int64(0), r.ContentLength)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
}

// --- Retry Logic Tests ---

func TestDoRequest_RetriesOn5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(500)
			w.Write([]byte(`server error`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	body, status, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, status)
	assert.Contains(t, string(body), "ok")
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

func TestDoRequest_FailsAfterAllRetriesExhausted(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(503)
		w.Write([]byte(`service unavailable`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "after 4 attempts")
	assert.Equal(t, int32(4), atomic.LoadInt32(&attempts))
}

func TestDoRequest_NoRetryOn4xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(400)
		w.Write([]byte(`bad request`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, status, err := c.DoRequest(context.Background(), "POST", "/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 400, status)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
}

func TestDoRequest_NoRetryOn404(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(404)
		w.Write([]byte(`not found`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, status, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 404, status)
	assert.True(t, IsNotFound(err))
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
}

// --- Redirect Tests ---

func TestDoRequest_RedirectReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(303)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, status, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 303, status)
	assert.True(t, IsRedirect(err))
	assert.Contains(t, err.Error(), "redirect to /login")
}

func TestDoRequest_301RedirectReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/new-path")
		w.WriteHeader(301)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, status, err := c.DoRequest(context.Background(), "GET", "/test", nil)
	assert.Error(t, err)
	assert.Equal(t, 301, status)
	assert.True(t, IsRedirect(err))
}

// --- URL Construction ---

func TestDoRequest_ConstructsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/about", r.URL.Path)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.DoRequest(context.Background(), "GET", "/xsoar/about", nil)
	assert.NoError(t, err)
}

// --- DoRequestRaw Tests ---

func TestDoRequestRaw_ReturnsBodyForAllStatusCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`not found`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	body, status, err := c.DoRequestRaw(context.Background(), "GET", "/test", nil)
	assert.NoError(t, err)
	assert.Equal(t, 404, status)
	assert.Equal(t, "not found", string(body))
}

// --- DetectVersion Tests ---

func TestDetectVersion_V6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"demistoVersion": "6.14.0",
			"buildNum":       "12345",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	majorVer, versionStr, deploymentMode, productMode, err := c.DetectVersion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 6, majorVer)
	assert.Equal(t, "6.14.0", versionStr)
	assert.Empty(t, deploymentMode)
	assert.Empty(t, productMode)
}

func TestDetectVersion_V8OPP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			w.WriteHeader(303)
			return
		}
		if r.URL.Path == "/xsoar/about" {
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"demistoVersion": "8.9.0",
			})
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	majorVer, _, deploymentMode, productMode, err := c.DetectVersion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 8, majorVer)
	assert.Equal(t, "opp", deploymentMode)
	assert.Empty(t, productMode)
}

func TestDetectVersion_V8SaaS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"demistoVersion": "8.13.0",
			"deploymentMode": "saas",
			"productMode":    "xsoar",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	majorVer, _, deploymentMode, productMode, err := c.DetectVersion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 8, majorVer)
	assert.Equal(t, "saas", deploymentMode)
	assert.Equal(t, "xsoar", productMode)
}

func TestDetectVersion_XSIAM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			w.WriteHeader(303)
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"demistoVersion": "8.13.0",
			"deploymentMode": "saas",
			"productMode":    "xsiam",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	majorVer, _, deploymentMode, productMode, err := c.DetectVersion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 8, majorVer)
	assert.Equal(t, "saas", deploymentMode)
	assert.Equal(t, "xsiam", productMode)
	assert.Equal(t, "xsiam", c.ProductMode)
}

// --- AccountScopedPath ---

func TestAccountScopedPath_WithAccount(t *testing.T) {
	c := &Client{}
	assert.Equal(t, "/acc_test123/jobs", c.AccountScopedPath("test123", "/jobs"))
}

func TestAccountScopedPath_EmptyAccount(t *testing.T) {
	c := &Client{}
	assert.Equal(t, "/jobs", c.AccountScopedPath("", "/jobs"))
}

// --- truncateMessage ---

func TestTruncateMessage(t *testing.T) {
	assert.Equal(t, "short", truncateMessage("short", 100))
	assert.Equal(t, "abc...", truncateMessage("abcdef", 3))
	assert.Equal(t, "", truncateMessage("", 10))
}
