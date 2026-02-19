package client

import "fmt"

// APIError represents an error response from the XSOAR API.
type APIError struct {
	StatusCode int
	Message    string
	Path       string
}

func (e *APIError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("XSOAR API error (HTTP %d) on %s: %s", e.StatusCode, e.Path, e.Message)
	}
	return fmt.Sprintf("XSOAR API error (HTTP %d): %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found.
func IsNotFound(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == 404
	}
	return false
}

// IsConflict returns true if the error is a 409 Conflict (version mismatch).
func IsConflict(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == 409
	}
	return false
}

// IsRedirect returns true if the error is a 3xx redirect response.
func IsRedirect(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode >= 300 && apiErr.StatusCode < 400
	}
	return false
}
