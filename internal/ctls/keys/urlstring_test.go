package keys

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustParseURL(t *testing.T, str string) *url.URL {
	parsed, err := url.Parse(str)
	if err != nil {
		t.FailNow()
	}

	return parsed
}

//

func Test_NewURLString(t *testing.T) {
	t.Run("invalid url", func(t *testing.T) {
		got := NewURLString(`"https://example.com/%zz"`)

		assert.Empty(t, got)
	})

	t.Run("valid url", func(t *testing.T) {
		got := NewURLString("wormhole.example.com")

		assert.Equal(t, "wormhole.example.com", got.Raw)
		assert.Equal(t, "wormhole.example.com", got.Key)
	})
}

func Test_URLString_UnmarshalJSON(t *testing.T) {
	t.Run("success with full url", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`"https://www.example.com/path?q=1"`))

		assert.NoError(t, err)
		assert.Equal(t, "https://www.example.com/path?q=1", u.Raw)
		assert.Equal(t, "example.com", u.Key)
		assert.NotNil(t, u.URL)
		assert.Equal(t, "https://www.example.com/path?q=1", u.URL.String())
	})

	t.Run("success with already normalized hostname string", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`"wormhole.example.com"`))

		assert.NoError(t, err)
		assert.Equal(t, "wormhole.example.com", u.Raw)
		assert.Equal(t, "wormhole.example.com", u.Key)
		assert.NotNil(t, u.URL)
		assert.Equal(t, "wormhole.example.com", u.URL.String())
	})

	t.Run("returns error for invalid json", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`not-json`))

		assert.Error(t, err)
		assert.Equal(t, "", u.Raw)
		assert.Equal(t, "", u.Key)
		assert.Nil(t, u.URL)
	})

	t.Run("returns error for non-string json", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`123`))

		assert.Error(t, err)
		assert.Equal(t, "", u.Raw)
		assert.Equal(t, "", u.Key)
		assert.Nil(t, u.URL)
	})

	t.Run("returns error for invalid url", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`"https://example.com/%zz"`))

		assert.Error(t, err)
		assert.Equal(t, "", u.Raw)
		assert.Equal(t, "", u.Key)
		assert.Nil(t, u.URL)
	})
}

func Test_URLString_MarshalJSON(t *testing.T) {
	t.Run("marshals raw value", func(t *testing.T) {
		u := URLString{
			Raw: "https://www.example.com/path?q=1",
			Key: "example.com",
			URL: mustParseURL(t, "https://www.example.com/path?q=1"),
		}

		got, err := u.MarshalJSON()

		assert.NoError(t, err)
		assert.Equal(t, `"https://www.example.com/path?q=1"`, string(got))
	})

	t.Run("round trip preserves raw string", func(t *testing.T) {
		var u URLString

		err := u.UnmarshalJSON([]byte(`"https://www.example.com/path?q=1"`))
		assert.NoError(t, err)

		got, err := u.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `"https://www.example.com/path?q=1"`, string(got))
	})

	t.Run("empty raw marshals as empty string", func(t *testing.T) {
		u := URLString{}

		got, err := u.MarshalJSON()

		assert.NoError(t, err)
		assert.Equal(t, `""`, string(got))
	})
}

func Test_normalizeURL(t *testing.T) {
	t.Run("previously normalized", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "wormhole.example.com"))
		assert.Equal(t, "wormhole.example.com", got)
	})

	t.Run("https example", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://wormhole.example.com"))
		assert.Equal(t, "wormhole.example.com", got)
	})

	t.Run("ignores path and query", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://wormhole.example.com/foo?test=who"))
		assert.Equal(t, "wormhole.example.com", got)
	})

	t.Run("ending slash", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://wormhole.example.com/"))
		assert.Equal(t, "wormhole.example.com", got)
	})

	t.Run("trims www prefix", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://www.example.com"))
		assert.Equal(t, "example.com", got)
	})

	t.Run("does not trim non-www subdomain", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://api.example.com"))
		assert.Equal(t, "api.example.com", got)
	})

	t.Run("strips port by using hostname", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "https://www.example.com:8443/path"))
		assert.Equal(t, "example.com", got)
	})

	t.Run("returns original string when hostname is empty", func(t *testing.T) {
		got := normalizeURL(mustParseURL(t, "/relative/path?x=1"))
		assert.Equal(t, "/relative/path?x=1", got)
	})
}
