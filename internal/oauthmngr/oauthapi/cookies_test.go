package oauthapi

import (
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

func Test_RemoveCookie(t *testing.T) {
	assert.Equal(t, "", RemoveCookie("", "_s"))
	assert.Equal(t, "a=1; _s_csrf=k; b=2", RemoveCookie("a=1; _s=v; _s_0=x; _s_csrf=k;; _s_1=y; b=2", "_s"))
	assert.Equal(t, "", RemoveCookie("_s=v; _s_0=x", "_s"), "removing every cookie yields an empty header")
	assert.Equal(t, "a=1; flag", RemoveCookie(" a=1 ;  _s =v; flag ", "_s"), "whitespace trimmed, valueless pairs kept")
}

func Test_RemoveFlowCookies(t *testing.T) {
	binding := BindingCookieName("n1")
	proof := AuthProofCookiePrefix + "n2"

	assert.Equal(t, "", RemoveFlowCookies(""))
	assert.Equal(t, "", RemoveFlowCookies(binding+"=x; "+proof+"=y"))
	assert.Equal(t,
		"a=1; _oauth2_proxy=s; b=2",
		RemoveFlowCookies("a=1; "+binding+"=x; _oauth2_proxy=s; "+proof+"=y; b=2"),
	)
	assert.Equal(t,
		"__Host-other=1; wormhole_oauth_flow_x=2",
		RemoveFlowCookies("__Host-other=1; wormhole_oauth_flow_x=2"),
		"only exact prefixes are stripped",
	)
}

func Test_ChunkName(t *testing.T) {
	assert.Equal(t, "_s_0", ChunkName("_s", 0))
	assert.Equal(t, "_s_12", ChunkName("_s", 12))
	assert.True(t, IsCookieOrChunk("_s", ChunkName("_s", MaxCookieChunks)))
}

func Test_JoinCookie_Boundaries(t *testing.T) {
	t.Run("exactly MaxCookieChunks is accepted", func(t *testing.T) {
		cookies := map[string]string{}
		for i := range MaxCookieChunks {
			cookies[ChunkName("_s", i)] = "x"
		}

		v, err := JoinCookie(cookies, "_s", SessionStoreCookie)

		require.NoError(t, err)
		assert.Len(t, v, MaxCookieChunks)
	})

	t.Run("redis accepts an unsplit cookie", func(t *testing.T) {
		v, err := JoinCookie(map[string]string{"_s": "ticket"}, "_s", SessionStoreRedis)

		require.NoError(t, err)
		assert.Equal(t, "ticket", v)
	})

	t.Run("redis rejects chunks even when the first is empty", func(t *testing.T) {
		_, err := JoinCookie(map[string]string{"_s_0": ""}, "_s", SessionStoreRedis)
		require.ErrorIs(t, err, ErrCookieChunked)
	})

	t.Run("empty unsplit cookie falls back to chunks", func(t *testing.T) {
		v, err := JoinCookie(map[string]string{"_s": "", "_s_0": "a", "_s_1": "b"}, "_s", SessionStoreCookie)

		require.NoError(t, err)
		assert.Equal(t, "ab", v)
	})

	t.Run("invalid store rejects chunks", func(t *testing.T) {
		_, err := JoinCookie(map[string]string{"_s_0": "a"}, "_s", SessionStore(""))
		require.ErrorIs(t, err, ErrCookieChunked)
	})

	t.Run("round trips with ParseCookies", func(t *testing.T) {
		v, err := JoinCookie(ParseCookies("other=1; _s_0=ab=; _s_1=cd"), "_s", SessionStoreCookie)

		require.NoError(t, err)
		assert.Equal(t, "ab=cd", v)
	})
}
