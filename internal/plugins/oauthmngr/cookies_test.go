package oauthmngr

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_cookieHeader(t *testing.T) {
	for _, scheme := range []string{"https", "http", "", "unknown"} {
		for _, path := range []string{"", "/", "/callback"} {
			for _, maxAge := range []int{-1, 0, 300} {
				header, err := cookieHeader("session", "abc|123==", path, maxAge, scheme)
				require.NoError(t, err)
				if path == "" {
					path = "/"
				}
				expected := &http.Cookie{
					Name: "session", Value: "abc|123==", Path: path, MaxAge: maxAge,
					HttpOnly: true, Secure: scheme != "http", SameSite: http.SameSiteLaxMode,
				}
				assert.Equal(t, expected.String(), header)
			}
		}
	}

	header, err := cookieHeader("binding", "", "/callback", -1, "https")
	require.NoError(t, err)
	assert.Equal(t, "binding=; Path=/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax", header)
}

func Test_cookieHeaderInvalid(t *testing.T) {
	for _, tc := range [][3]string{
		{"", "value", "/"},
		{"bad;name", "value", "/"},
		{"session", "value; Domain=example.com", "/"},
		{"session", "value\r\nInjected: yes", "/"},
		{"session", "a b", "/"},
		{"session", "a,b", "/"},
		{"session", "value", "relative"},
		{"session", "value", "/; Domain=example.com"},
		{"session", "value", "/\r\n"},
	} {
		header, err := cookieHeader(tc[0], tc[1], tc[2], 300, "https")
		require.Error(t, err, "%q", tc)
		assert.Empty(t, header)
	}
}
