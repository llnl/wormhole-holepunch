package oauthmngr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

//

func Test_noneManager_ExpandSources(t *testing.T) {
	m := newNoneManager()

	t.Run("returns nil sources unchanged", func(t *testing.T) {
		result := m.ExpandSources(nil)

		assert.Nil(t, result)
	})

	t.Run("returns empty sources unchanged", func(t *testing.T) {
		sources := []wormhole.RawSource{}

		result := m.ExpandSources(sources)

		assert.Equal(t, sources, result)
	})

	t.Run("returns sources unchanged", func(t *testing.T) {
		sources := []wormhole.RawSource{
			{ID: "source-a"},
			{ID: "source-b"},
		}

		result := m.ExpandSources(sources)

		assert.Equal(t, sources, result)
	})
}

//

func Test_noneManager_EstablishPreAuthFunc(t *testing.T) {
	m := newNoneManager()

	t.Run("returns a function that allows the request through without error", func(t *testing.T) {
		fn := m.EstablishPreAuthFunc(wormhole.RawSource{})

		skip, err := fn(requests.RequestDetails{})

		assert.False(t, skip)
		assert.Nil(t, err)
	})

	t.Run("returned function is consistent across multiple calls", func(t *testing.T) {
		fn := m.EstablishPreAuthFunc(wormhole.RawSource{})

		skip1, err1 := fn(requests.RequestDetails{Host: "example.com"})
		skip2, err2 := fn(requests.RequestDetails{Host: "other.com"})

		assert.False(t, skip1)
		assert.Nil(t, err1)

		assert.False(t, skip2)
		assert.Nil(t, err2)
	})
}

//

func Test_noneManager_PrepareAuthRedirect(t *testing.T) {
	m := newNoneManager()

	t.Run("returns empty string and internal error", func(t *testing.T) {
		redirect, err := m.PrepareAuthRedirect("https://example.com", requests.RequestDetails{})

		require.NotNil(t, err)
		assert.Equal(t, "", redirect)
		assert.Equal(t, int32(codes.Internal), err.Code())
	})

	t.Run("returns internal error regardless of proposed redirect", func(t *testing.T) {
		redirect, err := m.PrepareAuthRedirect("", requests.RequestDetails{})

		require.NotNil(t, err)
		assert.Equal(t, "", redirect)
		assert.Equal(t, int32(codes.Internal), err.Code())
	})
}

//

func Test_noneManager_RedirectHandler(t *testing.T) {
	m := newNoneManager()

	t.Run("returns nil cookie and internal error", func(t *testing.T) {
		cookie, err := m.RedirectHandler(context.Background(), requests.RequestDetails{})

		require.NotNil(t, err)
		assert.Nil(t, cookie)
		assert.Equal(t, int32(codes.Internal), err.Code())
	})
}

//

func Test_noneManager_ValidateCookies(t *testing.T) {
	m := newNoneManager()

	t.Run("returns empty result and auth error", func(t *testing.T) {
		result, err := m.ValidateCookies(context.Background(), requests.RequestDetails{})

		require.NotNil(t, err)
		assert.Equal(t, Result{}, result)
		assert.Equal(t, int32(codes.Unauthenticated), err.Code())
	})

	t.Run("passes the Cookie header through unchanged alongside the auth error", func(t *testing.T) {
		details := requests.RequestDetails{
			Headers: map[string]string{
				keys.CookieHeader: "session=token",
			},
		}

		result, err := m.ValidateCookies(context.Background(), details)

		require.NotNil(t, err)
		assert.Equal(t, Result{CookieHeader: "session=token"}, result)
		assert.Equal(t, int32(codes.Unauthenticated), err.Code())
	})
}
