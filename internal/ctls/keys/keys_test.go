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
