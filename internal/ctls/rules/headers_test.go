package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidateHeaderName(t *testing.T) {
	t.Run("disallowed", func(t *testing.T) {
		// "host" is in disallowedHeaders map
		err := ValidateHeaderName("Host") // exercise strings.ToLower path
		assert.ErrorContains(t, err, "not allowed")
	})

	t.Run("invalid token char", func(t *testing.T) {
		// Space is not a valid tchar.
		err := ValidateHeaderName("X Bad")
		assert.ErrorContains(t, err, "invalid header name")
	})

	t.Run("valid header name", func(t *testing.T) {
		err := ValidateHeaderName("X-Custom_Header.1~")
		assert.NoError(t, err)
	})
}

func Test_ValidateHeaderValue(t *testing.T) {
	t.Run("rejects control characters except HTAB", func(t *testing.T) {
		// NUL is a control char and not HTAB -> error
		err := ValidateHeaderValue("ok\x00bad")
		assert.ErrorContains(t, err, "invalid control character")
	})

	t.Run("allows HTAB", func(t *testing.T) {
		// HTAB is explicitly allowed.
		err := ValidateHeaderValue("a\tb")
		assert.NoError(t, err)
	})
}

func Test_isTokenChar(t *testing.T) {
	t.Run("alpha", func(t *testing.T) {
		assert.True(t, isTokenChar('a'))
		assert.True(t, isTokenChar('Z'))
	})

	t.Run("digit", func(t *testing.T) {
		assert.True(t, isTokenChar('0'))
		assert.True(t, isTokenChar('9'))
	})

	t.Run("allowed specials", func(t *testing.T) {
		for _, ch := range []rune{'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'} {
			assert.True(t, isTokenChar(ch), "expected %q to be token char", ch)
		}
	})

	t.Run("disallowed", func(t *testing.T) {
		for _, ch := range []rune{' ', ':', '(', ')', '/', '[', ']', '{', '}', '@', ',', ';', '\\', '"', '='} {
			assert.False(t, isTokenChar(ch), "expected %q to NOT be token char", ch)
		}
	})
}
