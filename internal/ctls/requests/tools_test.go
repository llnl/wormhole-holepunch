package requests

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentifyURL_HTTP_PathPresent(t *testing.T) {
	req := &http.Request{
		Host: "example.com",
		URL:  &url.URL{Path: "/a/b"},
		// TLS nil => http
		Header: make(http.Header),
	}

	assert.Equal(t, "http://example.com/a/b", IdentifyURL(req))
}

func TestIdentifyURL_HTTPS_PathPresent(t *testing.T) {
	req := &http.Request{
		Host:   "example.com",
		URL:    &url.URL{Path: "/secure"},
		TLS:    &tls.ConnectionState{}, // non-nil => https
		Header: make(http.Header),
	}

	assert.Equal(t, "https://example.com/secure", IdentifyURL(req))
}

func TestIdentifyURL_EmptyPath_UsesForwardedPrefix(t *testing.T) {
	req := &http.Request{
		Host:   "example.com",
		URL:    &url.URL{Path: ""},
		Header: make(http.Header),
	}
	req.Header.Set("X-Forwarded-Prefix", "/prefix")

	assert.Equal(t, "http://example.com/prefix", IdentifyURL(req))
}

func TestIdentifyPort_ExplicitValidPort(t *testing.T) {
	u := &url.URL{Scheme: "http", Host: "example.com:1234"}
	assert.Equal(t, uint32(1234), IdentifyPort(u))
}

func TestIdentifyPort_ExplicitInvalidPort_FallsBackToSchemeDefault(t *testing.T) {
	// url.URL.Port() returns the substring after the final colon, even if non-numeric.
	u := &url.URL{Scheme: "http", Host: "example.com:abc"}
	assert.Equal(t, uint32(80), IdentifyPort(u))
}

func TestIdentifyPort_NoPort_HTTPSDefault(t *testing.T) {
	u := &url.URL{Scheme: "https", Host: "example.com"}
	assert.Equal(t, uint32(443), IdentifyPort(u))
}

func TestIdentifyPort_NoPort_HTTPDefault(t *testing.T) {
	u := &url.URL{Scheme: "http", Host: "example.com"}
	assert.Equal(t, uint32(80), IdentifyPort(u))
}

func TestIdentifyPort_UnknownScheme_ReturnsZero(t *testing.T) {
	u := &url.URL{Scheme: "ftp", Host: "example.com"}
	assert.Equal(t, uint32(0), IdentifyPort(u))
}

func TestIsLocalhost_LocalhostAndLoopback(t *testing.T) {
	assert.True(t, IsLocalhost(&url.URL{Host: "localhost"}))
	assert.True(t, IsLocalhost(&url.URL{Host: "127.0.0.1"}))
	assert.True(t, IsLocalhost(&url.URL{Host: "127.0.0.42"}))
}

func TestIsLocalhost_NotLocalhost(t *testing.T) {
	assert.False(t, IsLocalhost(&url.URL{Host: "example.com"}))
	assert.False(t, IsLocalhost(&url.URL{Host: "128.0.0.1"}))
}

//

func Test_HeaderToStringMap(t *testing.T) {
	t.Run("nil header", func(t *testing.T) {
		var h http.Header // nil
		got := HeaderToStringMap(h)

		assert.NotNil(t, got)
		assert.Len(t, got, 0)
	})

	t.Run("empty header", func(t *testing.T) {
		h := http.Header{}
		got := HeaderToStringMap(h)

		assert.NotNil(t, got)
		assert.Len(t, got, 0)
	})

	t.Run("ignores empty values", func(t *testing.T) {
		h := http.Header{
			"X-Empty": {""},
		}
		got := HeaderToStringMap(h)

		assert.NotNil(t, got)
		assert.Len(t, got, 0)
		assert.NotContains(t, got, "x-empty")
	})

	t.Run("first non-empty wins", func(t *testing.T) {
		h := http.Header{
			"X-Test": {"", "v2", "v3"},
		}
		got := HeaderToStringMap(h)

		assert.NotNil(t, got)
		assert.Len(t, got, 1)
		assert.Equal(t, "v2", got["x-test"])
	})

	t.Run("mixed headers", func(t *testing.T) {
		h := http.Header{
			"X-A": {"a"},
			"X-B": {"", "b"},
			"X-C": {""},         // ignored
			"X-D": {"d1", "d2"}, // picks d1
			"X-E": {},           // ignored
		}
		got := HeaderToStringMap(h)

		assert.NotNil(t, got)
		assert.Len(t, got, 3)

		assert.Equal(t, "a", got["x-a"])
		assert.Equal(t, "b", got["x-b"])
		assert.Equal(t, "d1", got["x-d"])

		assert.NotContains(t, got, "x-c")
		assert.NotContains(t, got, "x-e")
	})
}

func Test_NormalizePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty path becomes slash",
			in:   "",
			want: "/",
		},
		{
			name: "root remains root",
			in:   "/",
			want: "/",
		},
		{
			name: "simple absolute path unchanged",
			in:   "/a/b",
			want: "/a/b",
		},
		{
			name: "relative path is prefixed with slash",
			in:   "a/b",
			want: "/a/b",
		},
		{
			name: "cleans dot segments",
			in:   "/a/./b/./c",
			want: "/a/b/c",
		},
		{
			name: "cleans double slashes",
			in:   "/a//b///c",
			want: "/a/b/c",
		},
		{
			name: "cleans dot-dot traversal within absolute path",
			in:   "/a/b/../c",
			want: "/a/c",
		},
		{
			name: "leading traversal in absolute path is clamped to root by path.Clean",
			in:   "/../../etc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "relative traversal is preserved then prefixed",
			in:   "../a",
			want: "/../a",
		},
		{
			name: "single dot is preserved then prefixed",
			in:   ".",
			want: "/.",
		},
		{
			name: "double dot is preserved then prefixed",
			in:   "..",
			want: "/..",
		},
		{
			name: "path.Clean removes trailing slash (except root)",
			in:   "/a/b/",
			want: "/a/b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u := &url.URL{Path: tt.in}
			got := NormalizePath(u)

			assert.Equal(t, tt.want, got)
		})
	}
}
