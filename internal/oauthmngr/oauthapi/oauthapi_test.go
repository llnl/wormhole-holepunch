package oauthapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_HTTPSOrigin(t *testing.T) {
	valid := map[string]string{
		"foo.example.com":       "https://foo.example.com",
		"Foo.Example.COM":       "https://foo.example.com",
		"foo.example.com:443":   "https://foo.example.com",
		"foo.example.com:0443":  "https://foo.example.com",
		"foo.example.com:8443":  "https://foo.example.com:8443",
		"foo.example.com:08443": "https://foo.example.com:8443",
		"foo.example.com.":      "https://foo.example.com.",
		"1.2.3.4":               "https://1.2.3.4",
		"1.2.3.4:443":           "https://1.2.3.4",
		"[::1]":                 "https://[::1]",
		"[::1]:443":             "https://[::1]",
		"[::1]:8443":            "https://[::1]:8443",
		"[0:0:0:0:0:0:0:1]":     "https://[::1]",
		"[FE80::1]":             "https://[fe80::1]",
		"[::ffff:1.2.3.4]":      "https://[::ffff:1.2.3.4]",
	}
	for authority, want := range valid {
		assert.Equal(t, want, HTTPSOrigin(authority), authority)
	}

	invalid := []string{
		"",
		":443",
		"foo.example.com:",
		"foo.example.com:abc",
		"foo.example.com:-1",
		"foo.example.com:+1",
		"foo.example.com:65536",
		"user@foo.example.com",
		"user:pass@foo.example.com",
		"foo.example.com/path",
		"foo.example.com?q",
		"foo.example.com#frag",
		"foo example.com",
		"foo_bar.example.com",
		"bücher.example",
		"::1",
		"[::1",
		"[]",
		"[not-an-ip]",
		"[fe80::1%25eth0]",
	}
	for _, authority := range invalid {
		assert.Empty(t, HTTPSOrigin(authority), authority)
	}
}

func Test_canonicalOriginHost(t *testing.T) {
	assert.Equal(t, "foo.example.com", canonicalOriginHost("foo.example.com"))
	assert.Equal(t, "[::1]", canonicalOriginHost("0:0::1"))
	assert.Empty(t, canonicalOriginHost("fe80::1%eth0"), "zoned addresses are rejected")
	assert.Empty(t, canonicalOriginHost("not:an:ip"))
	assert.Empty(t, canonicalOriginHost("FOO.example.com"), "callers must lowercase first")
	assert.Empty(t, canonicalOriginHost(""))
}

func Test_SameHTTPSAuthority(t *testing.T) {
	assert.True(t, SameHTTPSAuthority("foo.example.com", "foo.example.com"))
	assert.True(t, SameHTTPSAuthority("foo.example.com", "FOO.example.com:443"))
	assert.True(t, SameHTTPSAuthority("[::1]:8443", "[0:0:0:0:0:0:0:1]:8443"))
	assert.False(t, SameHTTPSAuthority("foo.example.com", "foo.example.com:8443"))
	assert.False(t, SameHTTPSAuthority("foo.example.com", "bar.example.com"))
	assert.False(t, SameHTTPSAuthority("foo.example.com", "foo.example.com."))
	assert.False(t, SameHTTPSAuthority("", ""), "two invalid authorities never match")
	assert.False(t, SameHTTPSAuthority("user@foo.example.com", "user@foo.example.com"))
}

func Test_ValidNonce(t *testing.T) {
	assert.False(t, ValidNonce(""))
	assert.False(t, ValidNonce("not-a-nonce"))
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAA=="), "padded encoding is rejected")
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAAAA"), "too long")
	assert.False(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAA+"), "standard alphabet is rejected")
	assert.True(t, ValidNonce("AAAAAAAAAAAAAAAAAAAAAA"))
}

func Test_LogSafeURL(t *testing.T) {
	assert.Equal(t, "https://foo.example.com/app/x", LogSafeURL("https://foo.example.com/app/x?sig=secret&a=b#frag"))
	assert.Equal(t, "https://foo.example.com/a%2Fb", LogSafeURL("https://user:pass@foo.example.com/a%2Fb?x=1"))
	assert.Equal(t, "https://foo.example.com", LogSafeURL("https://foo.example.com?token=x"))
	assert.Equal(t, "/", LogSafeURL("/?q=1"))
	assert.Equal(t, "<invalid url>", LogSafeURL("http://[::1"))
}

func Test_HostOnly(t *testing.T) {
	assert.Equal(t, "foo.example.com", HostOnly("foo.example.com"))
	assert.Equal(t, "foo.example.com", HostOnly("foo.example.com:8443"))
	assert.Equal(t, "::1", HostOnly("[::1]:8443"))
	assert.Equal(t, "::1", HostOnly("[::1]"))
	assert.Equal(t, "", HostOnly(""))
	assert.Equal(t, "::1", HostOnly("::1"), "unbracketed IPv6 is unchanged")
	assert.Equal(t, "10.0.0.1", HostOnly("10.0.0.1:51234"))
}
