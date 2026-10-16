package registry

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

// NoAuth is an admin only configuration, it must never be established by any JSON
// payload (route registry response or the JetStream messages derived from it).
func Test_RawSource_NoAuthNotDecodedFromJSON(t *testing.T) {
	tests := map[string]string{
		"snake case":  `"no_auth": true`,
		"field name":  `"NoAuth": true`,
		"lower case":  `"noauth": true`,
		"camel case":  `"noAuth": true`,
		"string":      `"no_auth": "true"`,
		"nested rule": `"rules": {"no_auth": true}`,
	}

	for name, field := range tests {
		t.Run(name, func(t *testing.T) {
			payload := `[{
				"id": "3d6527b5-9013-4255-a7b0-fe02e57756dc",
				"dst": "https://route.example.com",
				"src": "https://demo-src.example.com",
				` + field + `
			}]`

			var got []RawSource

			require.NoError(t, json.Unmarshal([]byte(payload), &got))
			require.Len(t, got, 1)
			assert.False(t, got[0].NoAuth)
		})
	}
}

func Test_RawSource_NoAuthNotEncodedToJSON(t *testing.T) {
	src, err := keys.NormalizeURL("https://noauth.example.com")
	require.NoError(t, err)

	dst, err := keys.NormalizeURL("https://foo.example.com")
	require.NoError(t, err)

	// Mirror PublishSources, which marshals a pointer to the slice.
	sources := []RawSource{{
		ID:          "3d6527b5-9013-4255-a7b0-fe02e57756dc",
		Source:      src,
		Destination: dst,
		NoAuth:      true,
	}}

	b, err := json.Marshal(&sources)
	require.NoError(t, err)

	assert.NotContains(t, string(b), "no_auth")
	assert.NotContains(t, string(b), "NoAuth")

	var got []RawSource

	require.NoError(t, json.Unmarshal(b, &got))
	require.Len(t, got, 1)
	assert.False(t, got[0].NoAuth)
}
