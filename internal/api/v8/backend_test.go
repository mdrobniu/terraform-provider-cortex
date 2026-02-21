package v8

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"terraform-provider-cortex/internal/client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBackend creates a V8 Backend pointing at the given test server.
func newTestBackend(t *testing.T, handler http.Handler, deploymentMode, productMode string) (*Backend, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c, err := client.NewClient(srv.URL, "test-key", true)
	require.NoError(t, err)
	c.RetryDelays = []time.Duration{0}
	b := NewBackend(c, deploymentMode, productMode)
	return b, srv
}

// --- Mode Helpers ---

func TestIsSaaS(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsoar")
	assert.True(t, b.isSaaS())
	b = NewBackend(&client.Client{}, "opp", "xsoar")
	assert.False(t, b.isSaaS())
}

func TestIsXSIAM(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	assert.True(t, b.isXSIAM())
	b = NewBackend(&client.Client{}, "opp", "xsoar")
	assert.False(t, b.isXSIAM())
}

func TestModeLabel(t *testing.T) {
	tests := []struct {
		deployment string
		product    string
		expected   string
	}{
		{"saas", "xsiam", "XSIAM"},
		{"saas", "xsoar", "XSOAR 8 SaaS"},
		{"opp", "xsoar", "XSOAR 8 OPP"},
		{"", "xsoar", "XSOAR 8 OPP"},
	}
	for _, tt := range tests {
		b := NewBackend(&client.Client{}, tt.deployment, tt.product)
		assert.Equal(t, tt.expected, b.modeLabel())
	}
}

// --- Path Prefix ---

func TestP_AddsXSOARPrefix(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	assert.Equal(t, "/xsoar/about", b.p("/about"))
	assert.Equal(t, "/xsoar/system/config", b.p("/system/config"))
	assert.Equal(t, "/xsoar/jobs/123", b.p("/jobs/123"))
}

// --- Server Config ---

func TestGetServerConfig_UsesXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/system/config", r.URL.Path)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sysConf": map[string]interface{}{"versn": float64(5)},
		})
	}), "opp", "xsoar")
	defer srv.Close()

	_, version, err := b.GetServerConfig()
	require.NoError(t, err)
	assert.Equal(t, 5, version)
}

func TestGetServerConfig_BlockedOnXSIAM(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	_, _, err := b.GetServerConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked on XSIAM")
}

func TestUpdateServerConfig_BlockedOnXSIAM(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	err := b.UpdateServerConfig(map[string]string{"key": "val"}, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked on XSIAM")
}

// --- Jobs ---

func TestCreateJob_UsesPOST_WithXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/jobs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "job-1", "name": "Test",
		})
	}), "opp", "xsoar")
	defer srv.Close()

	job, err := b.CreateJob(map[string]interface{}{"name": "Test"})
	require.NoError(t, err)
	assert.Equal(t, "job-1", job.ID)
}

func TestUpdateJob_UsesPOST_NotPUT(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/jobs", r.URL.Path)
		// Key gotcha: V8 job update uses POST, NOT PUT
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "job-1", "name": "Updated",
		})
	}), "opp", "xsoar")
	defer srv.Close()

	job, err := b.UpdateJob(map[string]interface{}{"id": "job-1", "name": "Updated"})
	require.NoError(t, err)
	assert.Equal(t, "job-1", job.ID)
}

func TestDeleteJob_UsesDELETE_WithXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/jobs/job-456", r.URL.Path)
		assert.Equal(t, "DELETE", r.Method)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}), "opp", "xsoar")
	defer srv.Close()

	err := b.DeleteJob("job-456")
	assert.NoError(t, err)
}

// --- Credentials ---

func TestCreateCredential_UsesPUT_WithXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/settings/credentials", r.URL.Path)
		assert.Equal(t, "PUT", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "cred-1", "name": "test", "user": "admin",
		})
	}), "opp", "xsoar")
	defer srv.Close()

	cred, err := b.CreateCredential(map[string]interface{}{
		"name": "test", "user": "admin", "password": "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "cred-1", cred.ID)
}

func TestDeleteCredential_UsesSingularID(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/settings/credentials/delete", r.URL.Path)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "my-cred", body["id"])
		_, hasIDs := body["ids"]
		assert.False(t, hasIDs)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}), "opp", "xsoar")
	defer srv.Close()

	err := b.DeleteCredential("my-cred")
	assert.NoError(t, err)
}

// --- Exclusion List ---

func TestGetExclusionList_UsesXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/indicators/whitelisted", r.URL.Path)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": "exc-1", "value": "192.168.0.0/16"},
		})
	}), "opp", "xsoar")
	defer srv.Close()

	entries, err := b.GetExclusionList()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.0.0/16", entries[0].Value)
}

// --- Roles ---

func TestCreateRole_ReturnsErrorOnV8(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	_, err := b.CreateRole(map[string]interface{}{"name": "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on XSOAR 8")
}

func TestDeleteRole_ReturnsErrorOnV8(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	err := b.DeleteRole("role-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on XSOAR 8")
}

// --- HA Groups / Hosts / Accounts not available on V8 ---

func TestHAGroups_NotAvailableOnV8(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	_, err := b.ListHAGroups()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestAccounts_NotAvailableOnV8(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	_, err := b.ListAccounts()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

// --- requireWebapp ---

func TestRequireWebapp_OPP_NoWebappClient(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	err := b.requireWebapp("external storage")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires session auth")
}

func TestRequireWebapp_SaaS_NoWebappClient(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsoar")
	err := b.requireWebapp("external storage")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session_token")
}

func TestRequireWebapp_XSIAM_NoWebappClient(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	err := b.requireWebapp("correlation rules")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session_token")
}

// --- requireXSIAMWebapp ---

func TestRequireXSIAMWebapp_NotXSIAM(t *testing.T) {
	b := NewBackend(&client.Client{}, "opp", "xsoar")
	err := b.requireXSIAMWebapp("correlation rules")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only available on XSIAM")
}

func TestRequireXSIAMWebapp_XSIAM_NoWebapp(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	err := b.requireXSIAMWebapp("correlation rules")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session_token")
}

func TestRequireXSIAMWebapp_XSIAM_WithWebapp(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsiam")
	b.WebappClient = &client.WebappClient{}
	err := b.requireXSIAMWebapp("correlation rules")
	assert.NoError(t, err)
}

// --- Preprocessing Rules on SaaS ---

func TestCreatePreprocessingRule_BlockedOnSaaS(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsoar")
	_, err := b.CreatePreprocessingRule(map[string]interface{}{"name": "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on XSOAR 8 SaaS")
}

// --- API Keys on SaaS ---

func TestCreateAPIKey_BlockedOnSaaS(t *testing.T) {
	b := NewBackend(&client.Client{}, "saas", "xsoar")
	_, err := b.CreateAPIKey("test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on XSOAR 8 SaaS")
}

// --- Marketplace with prefix ---

func TestListInstalledPacks_UsesXSOARPrefix(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/xsoar/contentpacks/metadata/installed", r.URL.Path)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": "Base", "name": "Base", "currentVersion": "1.0.0"},
		})
	}), "opp", "xsoar")
	defer srv.Close()

	packs, err := b.ListInstalledPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "Base", packs[0].ID)
}
