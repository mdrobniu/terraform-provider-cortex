package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIError_Error_WithPath(t *testing.T) {
	err := &APIError{StatusCode: 404, Message: "not found", Path: "/jobs/123"}
	assert.Contains(t, err.Error(), "HTTP 404")
	assert.Contains(t, err.Error(), "/jobs/123")
	assert.Contains(t, err.Error(), "not found")
}

func TestAPIError_Error_WithoutPath(t *testing.T) {
	err := &APIError{StatusCode: 500, Message: "internal error"}
	msg := err.Error()
	assert.Contains(t, msg, "HTTP 500")
	assert.Contains(t, msg, "internal error")
	assert.NotContains(t, msg, " on ")
}

func TestIsNotFound(t *testing.T) {
	assert.True(t, IsNotFound(&APIError{StatusCode: 404}))
	assert.False(t, IsNotFound(&APIError{StatusCode: 400}))
	assert.False(t, IsNotFound(&APIError{StatusCode: 500}))
	assert.False(t, IsNotFound(fmt.Errorf("generic error")))
	assert.False(t, IsNotFound(nil))
}

func TestIsConflict(t *testing.T) {
	assert.True(t, IsConflict(&APIError{StatusCode: 409}))
	assert.False(t, IsConflict(&APIError{StatusCode: 404}))
	assert.False(t, IsConflict(fmt.Errorf("generic error")))
}

func TestIsRedirect(t *testing.T) {
	assert.True(t, IsRedirect(&APIError{StatusCode: 301}))
	assert.True(t, IsRedirect(&APIError{StatusCode: 303}))
	assert.True(t, IsRedirect(&APIError{StatusCode: 399}))
	assert.False(t, IsRedirect(&APIError{StatusCode: 200}))
	assert.False(t, IsRedirect(&APIError{StatusCode: 400}))
	assert.False(t, IsRedirect(fmt.Errorf("generic error")))
}
