package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Keys(t *testing.T) {
	// We don't have any real output to compare here, just make sure the
	// functions can complete the request.
	t.Run("KeyWAT", func(t *testing.T) {
		got := WormholeAccessToken("tokenID")

		assert.NotEmpty(t, got)
	})

	t.Run("KeyWOS", func(t *testing.T) {
		got := WormholeOauthSession("access.token.example")

		assert.NotEmpty(t, got)
	})

	t.Run("KeyWAS", func(t *testing.T) {
		got := WormholeAccessSubtoken("parentID", "externalID")

		assert.NotEmpty(t, got)
	})
}

func Test_DefaultRemovableHeaders(t *testing.T) {
	t.Run("DefaultRemovableHeaders", func(t *testing.T) {
		got := DefaultRemovableHeaders()

		assert.GreaterOrEqual(t, len(got), 6)
	})
}

func Test_OAuthCallbackHeaders(t *testing.T) {
	assert.Equal(t, "access-control-allow-credentials", AccessControlAllowCredentialsHeader)
	assert.Equal(t, "access-control-allow-headers", AccessControlAllowHeadersHeader)
	assert.Equal(t, "access-control-allow-methods", AccessControlAllowMethodsHeader)
	assert.Equal(t, "access-control-allow-origin", AccessControlAllowOriginHeader)
	assert.Equal(t, "access-control-request-headers", AccessControlRequestHeadersHeader)
	assert.Equal(t, "access-control-request-method", AccessControlRequestMethodHeader)
	assert.Equal(t, "allow", AllowHeader)
	assert.Equal(t, "content-security-policy", ContentSecurityPolicyHeader)
	assert.Equal(t, "vary", VaryHeader)
	assert.Equal(t, "x-wormhole-oauth-code", WormholeOAuthCodeHeader)
	assert.Equal(t, "x-wormhole-oauth-proof", WormholeOAuthProofHeader)
}
