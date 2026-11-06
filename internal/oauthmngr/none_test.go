package oauthmngr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

func Test_noneManager_ExpandSources(t *testing.T) {
	m := newNoneManager()

	t.Run("returns empty sources for nil", func(t *testing.T) {
		assert.Empty(t, m.ExpandSources(nil))
	})

	t.Run("preserves sources without adding routes", func(t *testing.T) {
		sources := []registry.RawSource{
			source(t, "a", "https://foo.example.com/app"),
			source(t, "b", "https://foo.example.com/other"),
			source(t, "c", "https://bar.example.com/"),
		}

		expanded := m.ExpandSources(sources)

		assert.Equal(t, sources, expanded)
		assert.Empty(t, injected(expanded))
	})
}

func Test_noneManager_PrepareAuthRedirect(t *testing.T) {
	redirect, sErr := newNoneManager().PrepareAuthRedirect("https://foo.example.com/app", requests.RequestDetails{})

	require.NotNil(t, sErr)
	assert.Empty(t, redirect)
	assert.Equal(t, int32(codes.Internal), sErr.Code())
}

func Test_noneManager_ValidateCookies(t *testing.T) {
	result, sErr := newNoneManager().ValidateCookies(context.Background(), requests.RequestDetails{
		Headers: map[string]string{keys.CookieHeader: "foo=bar"},
	})

	require.NotNil(t, sErr)
	assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	assert.Empty(t, result.AccessToken)
	assert.Equal(t, "foo=bar", result.CookieHeader)
}

func Test_noneManager_WasmPluginConfig(t *testing.T) {
	cfg, ok := newNoneManager().WasmPluginConfig()

	assert.False(t, ok)
	assert.Nil(t, cfg)
}
