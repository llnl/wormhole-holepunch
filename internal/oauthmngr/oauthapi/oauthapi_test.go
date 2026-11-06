package oauthapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidNonce(t *testing.T) {
	assert.False(t, ValidNonce(""))
	assert.False(t, ValidNonce("not-a-nonce"))
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAA=="), "padded encoding is rejected")
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAAAA"), "too long")
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAA+"), "standard alphabet is rejected")
	assert.True(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAA"))
}

func Test_HostOnly(t *testing.T) {
	assert.Equal(t, "foo.example.com", HostOnly("foo.example.com"))
	assert.Equal(t, "foo.example.com", HostOnly("foo.example.com:8443"))
	assert.Equal(t, "::1", HostOnly("[::1]:8443"))
	assert.Equal(t, "::1", HostOnly("[::1]"))
	assert.Equal(t, "", HostOnly(""))
	assert.Equal(t, "::1", HostOnly("::1"), "unbracketed IPv6 is unchanged")
	assert.Equal(t, "10.0.0.1", HostOnly("10.0.0.1:51234"))
}
