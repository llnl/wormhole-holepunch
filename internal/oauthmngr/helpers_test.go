package oauthmngr

import (
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractCookie(t *testing.T) {
	t.Run("returns empty string for empty header", func(t *testing.T) {
		assert.Equal(t, "", extractCookie("", "session"))
	})

	t.Run("finds the requested cookie among several", func(t *testing.T) {
		header := "foo=bar; session=abc123; other=value"
		assert.Equal(t, "abc123", extractCookie(header, "session"))
	})

	t.Run("returns empty string when cookie is not present", func(t *testing.T) {
		header := "foo=bar; other=value"
		assert.Equal(t, "", extractCookie(header, "session"))
	})

	t.Run("trims surrounding whitespace around cookie pairs", func(t *testing.T) {
		header := "foo=bar;   session=abc123  ; other=value"
		assert.Equal(t, "abc123", extractCookie(header, "session"))
	})

	t.Run("preserves '=' characters within the cookie value", func(t *testing.T) {
		header := "session=abc123=="
		assert.Equal(t, "abc123==", extractCookie(header, "session"))
	})

	t.Run("returns first match when cookie name repeats", func(t *testing.T) {
		header := "session=first; session=second"
		assert.Equal(t, "first", extractCookie(header, "session"))
	})
}

func Test_NewURLString(t *testing.T) {
	t.Run("creates URLString from valid HTTP URL", func(t *testing.T) {
		rawURL := "http://example.com/path"

		result := keys.NewURLString(rawURL)

		require.NotNil(t, result.URL)
		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "/path", result.URL.Path)
	})

	t.Run("creates URLString from valid HTTPS URL", func(t *testing.T) {
		rawURL := "https://secure.example.com/api/v1"

		result := keys.NewURLString(rawURL)

		require.NotNil(t, result.URL)
		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "/api/v1", result.URL.Path)
	})

	t.Run("creates URLString from URL with port", func(t *testing.T) {
		rawURL := "http://example.com:8080/path"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "example.com", result.URL.Hostname())
		assert.Equal(t, "8080", result.URL.Port())
	})

	t.Run("creates URLString from URL with query parameters", func(t *testing.T) {
		rawURL := "https://example.com/path?key=value&foo=bar"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "key=value&foo=bar", result.URL.RawQuery)
	})

	t.Run("creates URLString from URL with fragment", func(t *testing.T) {
		rawURL := "https://example.com/path#section"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "section", result.URL.Fragment)
	})

	t.Run("normalizes www prefix in hostname", func(t *testing.T) {
		rawURL := "https://www.example.com/path"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "www.example.com", result.URL.Hostname())
	})

	t.Run("handles URL with basic auth", func(t *testing.T) {
		rawURL := "https://user:pass@example.com/path"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		username := result.URL.User.Username()
		password, _ := result.URL.User.Password()
		assert.Equal(t, "user", username)
		assert.Equal(t, "pass", password)
	})

	t.Run("handles localhost URL", func(t *testing.T) {
		rawURL := "http://localhost:3000/api"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "localhost", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "localhost", result.URL.Hostname())
	})

	t.Run("handles IP address URL", func(t *testing.T) {
		rawURL := "http://192.168.1.1:8080/path"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "192.168.1.1", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "192.168.1.1", result.URL.Hostname())
	})

	t.Run("handles IPv6 address URL", func(t *testing.T) {
		rawURL := "http://[2001:db8::1]:8080/path"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "2001:db8::1", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "2001:db8::1", result.URL.Hostname())
	})

	t.Run("returns empty URLString for invalid URL", func(t *testing.T) {
		rawURL := "://invalid-url"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, "", result.Raw)
		assert.Equal(t, "", result.Key)
		assert.Nil(t, result.URL)
	})

	t.Run("returns empty URLString for malformed URL", func(t *testing.T) {
		rawURL := "ht!tp://invalid url with spaces"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, "", result.Raw)
		assert.Equal(t, "", result.Key)
		assert.Nil(t, result.URL)
	})

	t.Run("handles URL with only scheme and host", func(t *testing.T) {
		rawURL := "https://example.com"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "example.com", result.URL.Hostname())
		assert.Equal(t, "", result.URL.Path)
	})

	t.Run("handles URL with subdomain", func(t *testing.T) {
		rawURL := "https://api.sub.example.com/v1"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "api.sub.example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "api.sub.example.com", result.URL.Hostname())
	})

	t.Run("handles URL with trailing slash", func(t *testing.T) {
		rawURL := "https://example.com/path/"

		result := keys.NewURLString(rawURL)

		assert.Equal(t, rawURL, result.Raw)
		assert.Equal(t, "example.com", result.Key)
		require.NotNil(t, result.URL)
		assert.Equal(t, "/path/", result.URL.Path)
	})
}
