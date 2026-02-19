package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Client is the XSOAR REST API client.
type Client struct {
	BaseURL        string
	APIKey         string
	AuthID         string // x-xdr-auth-id for XSOAR 8
	HTTPClient     *http.Client
	Version        int    // 6 or 8, detected from /about
	DeploymentMode string // "saas", "opp", or "" (V6)
}

// NewClient creates a new XSOAR API client.
func NewClient(baseURL, apiKey string, insecure bool) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		// Prevent following redirects - XSOAR uses 303 to signal "not available"
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		HTTPClient: httpClient,
	}, nil
}

// DoRequest executes an HTTP request with authentication headers and retry logic.
// Returns the response body, HTTP status code, and any error.
func (c *Client) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	var lastErr error
	retryDelays := []time.Duration{0, 1 * time.Second, 5 * time.Second, 15 * time.Second}

	for attempt, delay := range retryDelays {
		if delay > 0 {
			time.Sleep(delay)
		}

		// Re-create reader for retries
		if attempt > 0 && body != nil {
			jsonData, _ := json.Marshal(body)
			reqBody = bytes.NewBuffer(jsonData)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return nil, 0, fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("Authorization", c.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		// XSOAR 8 auth header
		if c.AuthID != "" {
			req.Header.Set("x-xdr-auth-id", c.AuthID)
		}

		tflog.Debug(ctx, fmt.Sprintf("XSOAR API %s %s (attempt %d)", method, path, attempt+1))

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("executing request %s %s: %w", method, path, err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response body: %w", err)
			continue
		}

		// Retry on 5xx errors
		if resp.StatusCode >= 500 {
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Message:    truncateMessage(string(respBody), 500),
				Path:       path,
			}
			continue
		}

		// Return 3xx redirects as errors (XSOAR uses 303 for "not available")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			msg := truncateMessage(string(respBody), 500)
			if location != "" {
				msg = fmt.Sprintf("redirect to %s: %s", location, msg)
			}
			return respBody, resp.StatusCode, &APIError{
				StatusCode: resp.StatusCode,
				Message:    msg,
				Path:       path,
			}
		}

		// Return 4xx errors immediately (no retry)
		if resp.StatusCode >= 400 {
			return respBody, resp.StatusCode, &APIError{
				StatusCode: resp.StatusCode,
				Message:    truncateMessage(string(respBody), 500),
				Path:       path,
			}
		}

		return respBody, resp.StatusCode, nil
	}

	return nil, 0, fmt.Errorf("after %d attempts: %w", len(retryDelays), lastErr)
}

// DoRequestRaw executes an HTTP request and returns the raw response body without error checking on status codes.
func (c *Client) DoRequestRaw(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.AuthID != "" {
		req.Header.Set("x-xdr-auth-id", c.AuthID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("reading response body: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// AccountScopedPath returns the path prefixed for account-scoped operations.
func (c *Client) AccountScopedPath(account, path string) string {
	if account == "" {
		return path
	}
	return fmt.Sprintf("/acc_%s%s", account, path)
}

// DetectVersion calls GET /about to determine the XSOAR version and deployment mode.
// For XSOAR 8, tries /xsoar/about as fallback if /about fails.
// Returns: majorVersion, versionString, deploymentMode ("saas", "opp", or ""), error
func (c *Client) DetectVersion(ctx context.Context) (int, string, string, error) {
	// Try standard /about first (works for V6)
	respBody, statusCode, err := c.DoRequestRaw(ctx, "GET", "/about", nil)
	if err != nil {
		return 0, "", "", fmt.Errorf("detecting XSOAR version: %w", err)
	}

	// If /about returns error or redirect, try /xsoar/about (XSOAR 8 pattern)
	if statusCode >= 300 {
		respBody, statusCode, err = c.DoRequestRaw(ctx, "GET", "/xsoar/about", nil)
		if err != nil {
			return 0, "", "", fmt.Errorf("detecting XSOAR version (V8 fallback): %w", err)
		}
		if statusCode >= 300 {
			return 0, "", "", fmt.Errorf("detecting XSOAR version: both /about and /xsoar/about failed (HTTP %d)", statusCode)
		}
	}

	var about map[string]interface{}
	if err := json.Unmarshal(respBody, &about); err != nil {
		// If /about returned non-JSON, try /xsoar/about
		respBody, statusCode, err = c.DoRequestRaw(ctx, "GET", "/xsoar/about", nil)
		if err != nil {
			return 0, "", "", fmt.Errorf("detecting XSOAR version (V8 fallback): %w", err)
		}
		if err := json.Unmarshal(respBody, &about); err != nil {
			return 0, "", "", fmt.Errorf("parsing /about response: %w", err)
		}
	}

	versionStr := ""
	if v, ok := about["demistoVersion"].(string); ok {
		versionStr = v
	}

	majorVer := 6
	if strings.HasPrefix(versionStr, "8") {
		majorVer = 8
	}

	// Parse deployment mode from /about response (XSOAR 8 only)
	deploymentMode := ""
	if majorVer == 8 {
		if dm, ok := about["deploymentMode"].(string); ok {
			deploymentMode = dm
		} else {
			// V8 without deploymentMode field defaults to OPP
			deploymentMode = "opp"
		}
	}

	c.Version = majorVer
	c.DeploymentMode = deploymentMode
	return majorVer, versionStr, deploymentMode, nil
}

func truncateMessage(msg string, maxLen int) string {
	if len(msg) > maxLen {
		return msg[:maxLen] + "..."
	}
	return msg
}
