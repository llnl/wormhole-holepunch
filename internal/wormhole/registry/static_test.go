package registry

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

func Test_loadStaticFile(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		got, err := loadStaticFile(logs.InitializeDiscard(), "")

		assert.NoError(t, err)
		assert.Len(t, got, 0)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		filename := t.TempDir() + "/invalid.yaml"
		os.WriteFile(filename, []byte("-1"), 0700)

		_, err := loadStaticFile(logs.InitializeDiscard(), filename)

		assert.Error(t, err)
	})

	t.Run("test data", func(t *testing.T) {
		got, err := loadStaticFile(logs.InitializeDiscard(), "../../../test/data/static.yaml")

		assert.NoError(t, err)
		assert.Len(t, got, 2)
		assert.Equal(t, "/foo", got[0].PrefixRewrite)
		assert.False(t, got[0].NoAuth)
		assert.False(t, got[1].NoAuth)
	})

	t.Run("no_auth decoded from yaml", func(t *testing.T) {
		filename := t.TempDir() + "/static.yaml"
		require.NoError(t, os.WriteFile(filename, []byte(`
sources:
  - id: "4ff69450-30eb-489b-bb90-15f25cd88c7d"
    dst: "https://foo.example.com"
    src: "https://noauth.example.com"
    prefix_rewrite: "/foo"
    no_auth: true
  - id: "43208434-df8d-4111-92ea-b29843e3f006"
    dst: "http://static.namespace.svc.cluster.local"
    src: "https://static.example.com"
    rules:
      allowed:
        users: [user1]
`), 0600))

		got, err := loadStaticFile(logs.InitializeDiscard(), filename)

		require.NoError(t, err)
		require.Len(t, got, 2)

		// Embedded RawSource fields must still be decoded alongside no_auth.
		assert.True(t, got[0].NoAuth)
		assert.Equal(t, "4ff69450-30eb-489b-bb90-15f25cd88c7d", got[0].ID)
		assert.Equal(t, "noauth.example.com", got[0].Source.Key)
		assert.Equal(t, "/foo", got[0].PrefixRewrite)

		assert.False(t, got[1].NoAuth)
		assert.Equal(t, []string{"user1"}, got[1].Rules.Allowed.Users)
	})

	t.Run("no_auth explicitly false", func(t *testing.T) {
		filename := t.TempDir() + "/static.yaml"
		require.NoError(t, os.WriteFile(filename, []byte(`
sources:
  - id: "4ff69450-30eb-489b-bb90-15f25cd88c7d"
    dst: "https://foo.example.com"
    src: "https://noauth.example.com"
    no_auth: false
`), 0600))

		got, err := loadStaticFile(logs.InitializeDiscard(), filename)

		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.False(t, got[0].NoAuth)
	})
}
