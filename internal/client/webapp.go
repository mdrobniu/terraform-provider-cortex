package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// WebappClient handles session-authenticated requests to the XSOAR 8 OPP webapp API.
// These endpoints live on the UI domain (not the API domain) and require session cookies
// obtained via username/password login.
type WebappClient struct {
	UIURL      string
	HTTPClient *http.Client
	csrfToken  string
	xsrfToken  string // Bearer JWT for x-xsrf-token header (XSIAM/SaaS)
}

// NewWebappClient creates a webapp client and authenticates via the login flow.
// The login flow is:
//  1. POST /api/users/public/login with {email, password} → JWT token
//  2. POST /login/local/callback with token=<jwt> (form-encoded) → session cookies
func NewWebappClient(ctx context.Context, uiURL, username, password string, insecure bool) (*WebappClient, error) {
	uiURL = strings.TrimRight(uiURL, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	wc := &WebappClient{
		UIURL:      uiURL,
		HTTPClient: httpClient,
	}

	if err := wc.login(ctx, username, password); err != nil {
		return nil, fmt.Errorf("webapp login failed: %w", err)
	}

	return wc, nil
}

// NewWebappClientFromToken creates a webapp client using a pre-obtained session cookie string.
// This is used for XSIAM and XSOAR 8 SaaS where SSO login is required and the user
// provides a session token extracted from browser DevTools.
func NewWebappClientFromToken(uiURL, sessionToken string, insecure bool) (*WebappClient, error) {
	uiURL = strings.TrimRight(uiURL, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Parse the UI URL to set cookies on the correct domain
	parsedURL, err := url.Parse(uiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing UI URL: %w", err)
	}

	// Set the session token as cookies on the UI domain
	cookies := []*http.Cookie{
		{
			Name:  "app-proxy-hydra-prod-us",
			Value: sessionToken,
			Path:  "/",
		},
		{
			Name:  "app-hub",
			Value: sessionToken,
			Path:  "/",
		},
	}
	jar.SetCookies(parsedURL, cookies)

	return &WebappClient{
		UIURL:      uiURL,
		HTTPClient: httpClient,
	}, nil
}

// SessionFile represents the structure of ~/.cortex/session.json.
type SessionFile struct {
	URL        string            `json:"url"`
	Cookies    map[string]string `json:"cookies"`
	AllCookies map[string]string `json:"all_cookies"`
	XSRFToken  string            `json:"xsrf_token"`
	CSRFToken  string            `json:"csrf_token"`
	Expiry     int64             `json:"expiry"`
}

// NewWebappClientFromSessionFile creates a webapp client from ~/.cortex/session.json.
// This is used when the cortex-login tool has been run to capture SSO session cookies.
func NewWebappClientFromSessionFile(insecure bool) (*WebappClient, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	sessionPath := filepath.Join(homeDir, ".cortex", "session.json")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no session file found at %s; run cortex-login first", sessionPath)
		}
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var session SessionFile
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("parsing session file: %w", err)
	}

	// Check expiry
	if session.Expiry > 0 && time.Now().Unix() > session.Expiry {
		return nil, fmt.Errorf("session expired at %s; run cortex-login to re-authenticate",
			time.Unix(session.Expiry, 0).Format(time.RFC3339))
	}

	if session.URL == "" {
		return nil, fmt.Errorf("session file missing URL")
	}

	uiURL := strings.TrimRight(session.URL, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	parsedURL, err := url.Parse(uiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing session URL: %w", err)
	}

	// Set all cookies from the session file
	cookieSource := session.AllCookies
	if len(cookieSource) == 0 {
		cookieSource = session.Cookies
	}
	var cookies []*http.Cookie
	for name, value := range cookieSource {
		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: value,
			Path:  "/",
		})
	}
	// Add XSRF-TOKEN and csrf_token as cookies (double-submit cookie pattern)
	if session.XSRFToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name:  "XSRF-TOKEN",
			Value: session.XSRFToken,
			Path:  "/",
		})
	}
	if session.CSRFToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name:  "csrf_token",
			Value: session.CSRFToken,
			Path:  "/",
		})
	}
	jar.SetCookies(parsedURL, cookies)

	wc := &WebappClient{
		UIURL:      uiURL,
		HTTPClient: httpClient,
		csrfToken:  session.CSRFToken,
		xsrfToken:  session.XSRFToken,
	}

	return wc, nil
}

// SessionFileURL returns the URL from the session file, or empty string if not available.
func SessionFileURL() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	sessionPath := filepath.Join(homeDir, ".cortex", "session.json")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return ""
	}
	var session SessionFile
	if err := json.Unmarshal(data, &session); err != nil {
		return ""
	}
	return session.URL
}

// login performs the two-step login flow to obtain session cookies.
func (wc *WebappClient) login(ctx context.Context, username, password string) error {
	tflog.Debug(ctx, "Webapp: logging in", map[string]interface{}{"ui_url": wc.UIURL, "username": username})

	// Step 1: POST /api/users/public/login → JWT token
	loginPayload, _ := json.Marshal(map[string]string{
		"email":    username,
		"password": password,
	})

	loginURL := fmt.Sprintf("%s/api/users/public/login", wc.UIURL)
	loginReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(string(loginPayload)))
	if err != nil {
		return fmt.Errorf("creating login request: %w", err)
	}
	loginReq.Header.Set("Content-Type", "application/json")

	loginResp, err := wc.HTTPClient.Do(loginReq)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer loginResp.Body.Close()

	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return fmt.Errorf("reading login response: %w", err)
	}

	if loginResp.StatusCode != 200 {
		return fmt.Errorf("login returned HTTP %d: %s", loginResp.StatusCode, truncateMessage(string(loginBody), 300))
	}

	var loginResult map[string]interface{}
	if err := json.Unmarshal(loginBody, &loginResult); err != nil {
		return fmt.Errorf("parsing login response: %w", err)
	}

	jwtToken, ok := loginResult["token"].(string)
	if !ok || jwtToken == "" {
		return fmt.Errorf("login response missing token field")
	}

	tflog.Debug(ctx, "Webapp: got JWT token, proceeding to callback")

	// Step 2: POST /login/local/callback with token=<jwt> → session cookies
	callbackURL := fmt.Sprintf("%s/login/local/callback", wc.UIURL)
	formData := url.Values{"token": {jwtToken}}
	callbackReq, err := http.NewRequestWithContext(ctx, "POST", callbackURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("creating callback request: %w", err)
	}
	callbackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	callbackResp, err := wc.HTTPClient.Do(callbackReq)
	if err != nil {
		return fmt.Errorf("callback request failed: %w", err)
	}
	defer callbackResp.Body.Close()
	io.ReadAll(callbackResp.Body) // consume body

	// Extract CSRF token from cookies
	parsedURL, _ := url.Parse(wc.UIURL)
	for _, cookie := range wc.HTTPClient.Jar.Cookies(parsedURL) {
		if cookie.Name == "csrf_token" {
			wc.csrfToken = cookie.Value
		}
	}

	if wc.csrfToken == "" {
		tflog.Warn(ctx, "Webapp: no csrf_token cookie found after login; requests may fail")
	}

	tflog.Info(ctx, "Webapp: session auth successful", map[string]interface{}{
		"ui_url":         wc.UIURL,
		"has_csrf_token": wc.csrfToken != "",
	})

	return nil
}

// DoRequest executes an authenticated request to the webapp API.
// It adds session cookies (via cookie jar), CSRF token, and required headers.
func (wc *WebappClient) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = strings.NewReader(string(jsonData))
	}

	reqURL := fmt.Sprintf("%s%s", wc.UIURL, path)

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-XDR-REQUEST-TOKEN", randomToken())
	if wc.csrfToken != "" {
		req.Header.Set("X-CSRF-TOKEN", wc.csrfToken)
	}
	if wc.xsrfToken != "" {
		req.Header.Set("X-XSRF-TOKEN", wc.xsrfToken)
	}

	tflog.Debug(ctx, fmt.Sprintf("Webapp API %s %s", method, path))

	resp, err := wc.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing webapp request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("reading webapp response body: %w", err)
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		return respBody, resp.StatusCode, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("redirect to %s (session may be expired; re-run cortex-login)", location),
			Path:       path,
		}
	}

	if resp.StatusCode >= 400 {
		return respBody, resp.StatusCode, &APIError{
			StatusCode: resp.StatusCode,
			Message:    truncateMessage(string(respBody), 500),
			Path:       path,
		}
	}

	return respBody, resp.StatusCode, nil
}

// randomToken generates a random hex token for the X-XDR-REQUEST-TOKEN header.
func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
