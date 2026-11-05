package cookies

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewResponse(t *testing.T) {
	for _, scheme := range []string{"https", "http", "", "unknown"} {
		t.Run(scheme, func(t *testing.T) {
			cookie, err := NewResponse("session", "abc|123==", Options{
				Path: "/callback", MaxAge: 300, Scheme: scheme,
			})
			require.NoError(t, err)
			assert.Equal(t, &http.Cookie{
				Name: "session", Value: "abc|123==", Path: "/callback", MaxAge: 300,
				HttpOnly: true, Secure: scheme != "http", SameSite: http.SameSiteLaxMode,
			}, cookie)
			require.NoError(t, cookie.Valid())

			parsed, err := http.ParseSetCookie(cookie.String())
			require.NoError(t, err)
			assert.Equal(t, cookie.Name, parsed.Name)
			assert.Equal(t, cookie.Value, parsed.Value)
			assert.Equal(t, cookie.Path, parsed.Path)
			assert.Equal(t, cookie.MaxAge, parsed.MaxAge)
			assert.Equal(t, cookie.Secure, parsed.Secure)
			assert.True(t, parsed.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, parsed.SameSite)
			assert.Empty(t, parsed.Domain)
		})
	}

	t.Run("session cookie defaults to the root path", func(t *testing.T) {
		cookie, err := NewResponse("session", "value", Options{})
		require.NoError(t, err)
		assert.Equal(t, "/", cookie.Path)
		assert.True(t, cookie.Secure)
		assert.NotContains(t, cookie.String(), "Max-Age")
	})

	t.Run("negative max age expires a cookie on the same path", func(t *testing.T) {
		cookie, err := NewResponse("binding", "", Options{Path: "/callback", MaxAge: -1, Scheme: "https"})
		require.NoError(t, err)
		assert.Equal(t, "binding=; Path=/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax", cookie.String())
	})

	tests := map[string]struct {
		name  string
		value string
		path  string
	}{
		"empty name":    {value: "value"},
		"invalid name":  {name: "bad;name", value: "value"},
		"unsafe value":  {name: "session", value: "value; Domain=example.com"},
		"header break":  {name: "session", value: "value\r\nX-Injected: yes"},
		"relative path": {name: "session", value: "value", path: "callback"},
		"unsafe path":   {name: "session", value: "value", path: "/; Domain=example.com"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cookie, err := NewResponse(tc.name, tc.value, Options{Path: tc.path})
			require.Error(t, err)
			assert.Nil(t, cookie)
		})
	}
}

func Test_validationMatchesHTTP(t *testing.T) {
	for i := range 256 {
		c := string([]byte{byte(i)})
		for _, pair := range [][2]string{{"n" + c, "value"}, {"name", "v" + c}} {
			want := (&http.Cookie{Name: pair[0], Value: pair[1]}).Valid()
			_, got := NewRequest(pair[0], pair[1])
			assert.Equal(t, want == nil, got == nil, "name/value: %q", pair)
		}
		path := "/" + c
		want := (&http.Cookie{Name: "name", Value: "value", Path: path}).Valid()
		_, got := NewResponse("name", "value", Options{Path: path})
		assert.Equal(t, want == nil, got == nil, "path: %q", path)
	}
}

func Test_NewRequest(t *testing.T) {
	cookie, err := NewRequest("_oauth2_proxy", "session")
	require.NoError(t, err)
	assert.Equal(t, &http.Cookie{Name: "_oauth2_proxy", Value: "session"}, cookie)

	for _, tc := range [][2]string{{"", "value"}, {"bad;name", "value"}, {"session", "bad\r\nvalue"}} {
		cookie, err := NewRequest(tc[0], tc[1])
		require.Error(t, err)
		assert.Nil(t, cookie)
	}
}
