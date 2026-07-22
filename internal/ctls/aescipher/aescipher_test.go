package aescipher

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 32-byte key
const testKey = "0123456789abcdef0123456789abcdef"

// Helpers to avoid importing encoding/base64 in every test file section; still 100% coverage.
func base64RawURLEncode(b []byte) string {
	// inline to keep tests self-contained while using same encoding as implementation
	// (we still import only what we need in this file).
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	return rawURLEncode(b, encodeStd)
}

func base64RawURLDecode(s string) ([]byte, error) {
	// Use the real decoder indirectly by recreating behavior with encoding/base64 would be silly;
	// but to keep tests minimal, we just import encoding/base64 here.
	// (Go allows adding imports; kept as helpers for readability.)
	return decodeRawURL(s)
}

func rawURLEncode(b []byte, _ string) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeRawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

//

func Test_New(t *testing.T) {
	t.Run("invalid key lengths", func(t *testing.T) {
		invalid := []string{
			"short", strings.Repeat("a", 15), strings.Repeat("a", 17),
			strings.Repeat("a", 23), strings.Repeat("a", 25),
			strings.Repeat("a", 31), strings.Repeat("a", 33),
		}

		for _, k := range invalid {
			_, err := New(k)

			assert.Error(t, err)
		}
	})

	t.Run("valid raw key lengths", func(t *testing.T) {
		valid := []string{
			strings.Repeat("a", 16),
			strings.Repeat("b", 24),
			strings.Repeat("c", 32),
		}

		for _, k := range valid {
			_, err := New(k)

			assert.NoError(t, err, "len=%d", len(k))
		}
	})

	t.Run("valid base64 keys (std and url, padded and raw) for 16/24/32 bytes", func(t *testing.T) {
		sizes := []int{16, 24, 32}

		for _, n := range sizes {
			raw := make([]byte, n)
			for i := range raw {
				raw[i] = byte(i) // deterministic
			}

			cases := map[string]string{
				"RawURLEncoding": base64.RawURLEncoding.EncodeToString(raw),
				"URLEncoding":    base64.URLEncoding.EncodeToString(raw),
				"RawStdEncoding": base64.RawStdEncoding.EncodeToString(raw),
				"StdEncoding":    base64.StdEncoding.EncodeToString(raw),
			}

			for name, enc := range cases {
				t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
					_, err := New(enc)

					assert.NoError(t, err)
				})
			}
		}
	})

	t.Run("generate key", func(t *testing.T) {
		key := GenerateKey()

		_, err := New(key)

		assert.NoError(t, err)
	})
}

func Test_NoopCipher(t *testing.T) {
	noop, err := New("")
	assert.NoError(t, err, "New")

	t.Run("encrypt", func(t *testing.T) {
		got, err := noop.Encrypt("foo")

		assert.NoError(t, err)
		assert.Equal(t, "foo", got)
	})

	t.Run("decrypt", func(t *testing.T) {
		got, err := noop.Decrypt("foo")

		assert.NoError(t, err)
		assert.Equal(t, "foo", got)
	})

	t.Run("decrypt and compare", func(t *testing.T) {
		got, err := noop.DecryptAndCompare("foo", "foo")

		assert.NoError(t, err)
		assert.True(t, got)
	})

}

func Test_Encrypt(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		plain := "hello, world"
		token, err := c.Encrypt(plain)

		assert.NoError(t, err, "Encrypt")
		assert.NotEmpty(t, token)

		got, err := c.Decrypt(token)

		assert.NoError(t, err, "Dencrypt")
		assert.Equal(t, plain, got)
	})
}

func Test_Decrypt_InvalidBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		_, err = c.Decrypt("%%%not-base64%%%")

		assert.Error(t, err, "Decrypt")
	})

	t.Run("token too short", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		// Valid base64url but decodes to < nonceSize (GCM nonce is 12 bytes).
		shortRaw := []byte("12345678901") // 11 bytes
		shortToken := base64RawURLEncode(shortRaw)

		_, err = c.Decrypt(shortToken)

		assert.Error(t, err, "Decrypt")
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		token, err := c.Encrypt("secret")
		assert.NoError(t, err, "Encrypt")

		raw, err := base64RawURLDecode(token)
		assert.NoError(t, err, "base64RawURLDecode")

		// Flip one bit in ciphertext/tag area (after nonce).
		if len(raw) <= 12 {
			t.Fatalf("unexpected raw length %d", len(raw))
		}
		raw[len(raw)-1] ^= 0x01
		tampered := base64RawURLEncode(raw)

		_, err = c.Decrypt(tampered)

		assert.Error(t, err, "Decrypt")
	})
}

func Test_DecryptAndCompare(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		token, err := c.Encrypt("abc")
		assert.NoError(t, err, "Encrypt")

		ok, err := c.DecryptAndCompare(token, "abc")

		assert.NoError(t, err, "DecryptAndCompare")
		assert.True(t, ok)
	})

	t.Run("length mismatch", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		token, err := c.Encrypt("abc")
		assert.NoError(t, err, "Encrypt")

		ok, err := c.DecryptAndCompare(token, "abcd")

		assert.NoError(t, err, "DecryptAndCompare")
		assert.False(t, ok)
	})

	t.Run("token mismatch", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		token, err := c.Encrypt("abc")
		assert.NoError(t, err, "Encrypt")

		ok, err := c.DecryptAndCompare(token, "xyz")

		assert.NoError(t, err, "DecryptAndCompare")
		assert.False(t, ok)
	})

	t.Run("decrypt error", func(t *testing.T) {
		c, err := New(testKey)
		assert.NoError(t, err, "New")

		ok, err := c.DecryptAndCompare("not-base64", "anything")

		assert.Error(t, err, "DecryptAndCompare")
		assert.False(t, ok)
	})
}
