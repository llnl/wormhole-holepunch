package requests

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestFailedError_Error_NilErr(t *testing.T) {
	e := &RequestFailedError{Err: nil}
	assert.Equal(t, "<nil>", e.Error())
}

func TestRequestFailedError_Error_WithStatusCode(t *testing.T) {
	under := errors.New("boom")
	e := &RequestFailedError{
		Err:        under,
		StatusCode: 418,
		URL:        "https://example.com/x",
	}

	assert.Equal(t, "request to https://example.com/x failed (status=418): boom", e.Error())
}

func TestRequestFailedError_Error_InternalFailure_NoStatusCode(t *testing.T) {
	under := errors.New("boom")
	e := &RequestFailedError{
		Err:        under,
		StatusCode: 0,
		URL:        "https://example.com/ignored",
	}

	assert.Equal(t, "internal request failure: boom", e.Error())
}

func TestRequestFailedError_Unwrap_Code_And_IsRequestFailedError(t *testing.T) {
	under := errors.New("root")
	e := &RequestFailedError{
		Err:        under,
		StatusCode: 500,
		URL:        "https://example.com",
	}

	assert.Same(t, under, e.Unwrap())
	assert.Equal(t, 500, e.Code())

	// Direct
	assert.True(t, IsRequestFailedError(e))

	// Wrapped (errors.As should still find it)
	wrapped := errors.Join(errors.New("outer"), e)
	assert.True(t, IsRequestFailedError(wrapped))

	// Non-matching error
	assert.False(t, IsRequestFailedError(errors.New("not it")))
}
