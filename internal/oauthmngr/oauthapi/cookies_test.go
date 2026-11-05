package oauthapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SessionStore_Valid(t *testing.T) {
	assert.True(t, SessionStoreCookie.Valid())
	assert.True(t, SessionStoreRedis.Valid())
	assert.False(t, SessionStore("").Valid())
	assert.False(t, SessionStore("memcached").Valid())
}

func Test_BindingCookieName(t *testing.T) {
	assert.Equal(t, BindingCookiePrefix+"nonce", BindingCookieName("nonce"))
}

func Test_ParseCookies(t *testing.T) {
	assert.Empty(t, ParseCookies(""))
	assert.Equal(t,
		map[string]string{"a": "1", "b": "x=y", "c": ""},
		ParseCookies("a=1;  b=x=y ; malformed; =nameless", "c=; a=2"),
		"first occurrence wins across headers, '=' preserved in values",
	)
}

func Test_IsCookieOrChunk(t *testing.T) {
	assert.True(t, IsCookieOrChunk("_s", "_s"))
	assert.True(t, IsCookieOrChunk("_s", "_s_0"))
	assert.True(t, IsCookieOrChunk("_s", "_s_12"))
	assert.False(t, IsCookieOrChunk("_s", "_s_"))
	assert.False(t, IsCookieOrChunk("_s", "_s_x"))
	assert.False(t, IsCookieOrChunk("_s", "_s_csrf"))
	assert.False(t, IsCookieOrChunk("_s", "_session"))
}

func Test_JoinCookie(t *testing.T) {
	t.Run("unsplit cookie takes precedence over chunks", func(t *testing.T) {
		v, err := JoinCookie(map[string]string{"_s": "whole", "_s_0": "part"}, "_s", SessionStoreCookie)

		require.NoError(t, err)
		assert.Equal(t, "whole", v)
	})

	t.Run("joins consecutive chunks", func(t *testing.T) {
		v, err := JoinCookie(map[string]string{"_s_0": "a", "_s_1": "b", "_s_2": "c", "_s_4": "gap"}, "_s", SessionStoreCookie)

		require.NoError(t, err)
		assert.Equal(t, "abc", v)
	})

	t.Run("redis rejects chunks", func(t *testing.T) {
		_, err := JoinCookie(map[string]string{"_s_0": "a"}, "_s", SessionStoreRedis)
		require.ErrorIs(t, err, ErrCookieChunked)
	})

	t.Run("too many chunks", func(t *testing.T) {
		cookies := map[string]string{}
		for i := range MaxCookieChunks + 1 {
			cookies[ChunkName("_s", i)] = "x"
		}

		_, err := JoinCookie(cookies, "_s", SessionStoreCookie)
		require.ErrorIs(t, err, ErrCookieTooLarge)
	})

	t.Run("missing", func(t *testing.T) {
		for _, cookies := range []map[string]string{{}, {"_s": ""}, {"_s_0": ""}, {"_s_1": "orphan"}} {
			_, err := JoinCookie(cookies, "_s", SessionStoreCookie)
			require.ErrorIs(t, err, ErrCookieNotFound, cookies)
		}
	})
}

func Test_SplitCookie(t *testing.T) {
	t.Run("fits in a single cookie for either store", func(t *testing.T) {
		value := strings.Repeat("a", CookieChunkSize)

		for _, store := range []SessionStore{SessionStoreCookie, SessionStoreRedis} {
			pairs, err := SplitCookie("_s", value, store)

			require.NoError(t, err)
			assert.Equal(t, [][2]string{{"_s", value}}, pairs)
		}
	})

	t.Run("chunked with the cookie store and round trips", func(t *testing.T) {
		value := strings.Repeat("a", CookieChunkSize) + strings.Repeat("b", CookieChunkSize) + "c"

		pairs, err := SplitCookie("_s", value, SessionStoreCookie)
		require.NoError(t, err)
		require.Len(t, pairs, 3)

		cookies := map[string]string{}
		for i, p := range pairs {
			assert.Equal(t, ChunkName("_s", i), p[0])
			assert.LessOrEqual(t, len(p[1]), CookieChunkSize)
			cookies[p[0]] = p[1]
		}

		joined, err := JoinCookie(cookies, "_s", SessionStoreCookie)
		require.NoError(t, err)
		assert.Equal(t, value, joined)
	})

	t.Run("redis rejects oversized sessions", func(t *testing.T) {
		_, err := SplitCookie("_s", strings.Repeat("a", CookieChunkSize+1), SessionStoreRedis)
		require.ErrorIs(t, err, ErrCookieTooLarge)
	})

	t.Run("bounded by MaxCookieChunks", func(t *testing.T) {
		_, err := SplitCookie("_s", strings.Repeat("a", CookieChunkSize*MaxCookieChunks), SessionStoreCookie)
		require.NoError(t, err)

		_, err = SplitCookie("_s", strings.Repeat("a", CookieChunkSize*MaxCookieChunks+1), SessionStoreCookie)
		require.ErrorIs(t, err, ErrCookieTooLarge)
	})
}

func Test_RemoveCookie(t *testing.T) {
	assert.Equal(t, "", RemoveCookie("", "_s"))
	assert.Equal(t, "a=1; _s_csrf=k; b=2", RemoveCookie("a=1; _s=v; _s_0=x; _s_csrf=k;; _s_1=y; b=2", "_s"))
}
