package v6

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

// newTestBackend creates a V6 Backend pointing at the given test server.
func newTestBackend(t *testing.T, handler http.Handler) (*Backend, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c, err := client.NewClient(srv.URL, "test-key", true)
	require.NoError(t, err)
	c.RetryDelays = []time.Duration{0}
	b := NewBackend(c)
	return b, srv
}

// --- Server Config ---

func TestGetServerConfig_UsesCorrectPath(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/system/config", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sysConf": map[string]interface{}{
				"versn":     float64(3),
				"some.key":  "some-value",
			},
		})
	}))
	defer srv.Close()

	conf, version, err := b.GetServerConfig()
	require.NoError(t, err)
	assert.Equal(t, 3, version)
	assert.Equal(t, "some-value", conf["some.key"])
}

func TestUpdateServerConfig_UsesPOST(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/system/config", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, float64(3), body["version"])
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := b.UpdateServerConfig(map[string]string{"key": "val"}, 3)
	assert.NoError(t, err)
}

// --- Jobs ---

func TestCreateJob_UsesPOST(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/jobs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "job-1",
			"name": "Test Job",
		})
	}))
	defer srv.Close()

	job, err := b.CreateJob(map[string]interface{}{"name": "Test Job"})
	require.NoError(t, err)
	assert.Equal(t, "job-1", job.ID)
}

func TestUpdateJob_UsesPOST_NotPUT(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/jobs", r.URL.Path)
		// Key gotcha: V6 job update uses POST, NOT PUT
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "job-1",
			"name": "Updated Job",
		})
	}))
	defer srv.Close()

	job, err := b.UpdateJob(map[string]interface{}{"id": "job-1", "name": "Updated Job"})
	require.NoError(t, err)
	assert.Equal(t, "job-1", job.ID)
}

func TestDeleteJob_UsesDELETE(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/jobs/job-123", r.URL.Path)
		assert.Equal(t, "DELETE", r.Method)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := b.DeleteJob("job-123")
	assert.NoError(t, err)
}

func TestCreateJob_DefaultsTypeToUnclassified(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "Unclassified", body["type"])
		json.NewEncoder(w).Encode(map[string]interface{}{"id": "job-1", "name": "test"})
	}))
	defer srv.Close()

	_, err := b.CreateJob(map[string]interface{}{"name": "test"})
	assert.NoError(t, err)
}

// --- Credentials ---

func TestCreateCredential_UsesPUT(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/settings/credentials", r.URL.Path)
		assert.Equal(t, "PUT", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "cred-1",
			"name": "test-cred",
			"user": "admin",
		})
	}))
	defer srv.Close()

	cred, err := b.CreateCredential(map[string]interface{}{
		"name": "test-cred", "user": "admin", "password": "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "cred-1", cred.ID)
}

func TestDeleteCredential_UsesSingularID(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/settings/credentials/delete", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		// Key gotcha: uses {id: "name"} NOT {ids: ["name"]}
		assert.Equal(t, "my-cred", body["id"])
		_, hasIDs := body["ids"]
		assert.False(t, hasIDs, "should not use 'ids' field")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := b.DeleteCredential("my-cred")
	assert.NoError(t, err)
}

// --- Exclusion List ---

func TestGetExclusionList_UsesCorrectPath(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/indicators/whitelisted", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": "exc-1", "value": "1.2.3.4", "type": "CIDR", "reason": "test"},
		})
	}))
	defer srv.Close()

	entries, err := b.GetExclusionList()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "1.2.3.4", entries[0].Value)
	assert.Equal(t, "CIDR", entries[0].Type)
}

func TestAddExclusion_UsesCorrectPath(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/indicators/whitelist/update", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "exc-1", "value": "10.0.0.0/8", "type": "CIDR", "reason": "internal",
		})
	}))
	defer srv.Close()

	entry, err := b.AddExclusion(map[string]interface{}{
		"value": "10.0.0.0/8", "type": "CIDR", "reason": "internal",
	})
	require.NoError(t, err)
	assert.Equal(t, "exc-1", entry.ID)
}

func TestRemoveExclusion_UsesCorrectPath(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/indicators/whitelist/remove", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		dataArr, ok := body["data"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "exc-1", dataArr[0])
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := b.RemoveExclusion("exc-1")
	assert.NoError(t, err)
}

// --- V6-only features ---

func TestListExternalStorage_ReturnsErrorOnV6(t *testing.T) {
	b := NewBackend(&client.Client{})
	_, err := b.ListExternalStorage()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available on XSOAR 6")
}

func TestListBackupSchedules_ReturnsErrorOnV6(t *testing.T) {
	b := NewBackend(&client.Client{})
	_, err := b.ListBackupSchedules()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available on XSOAR 6")
}

// --- Password Policy ---

func TestGetPasswordPolicy_UsesCorrectPath(t *testing.T) {
	b, srv := newTestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/settings/password-policy", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":           true,
			"version":           float64(1),
			"minPasswordLength": float64(8),
		})
	}))
	defer srv.Close()

	policy, err := b.GetPasswordPolicy()
	require.NoError(t, err)
	assert.True(t, policy.Enabled)
	assert.Equal(t, 8, policy.MinPasswordLength)
}
