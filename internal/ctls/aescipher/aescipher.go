// Package aescipher provides simple AES-GCM encrypt/decrypt helpers meant
// to assist in caching (in-memory) potential secrets.
package aescipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
)

const (
	keySize = 32 // AES-256
)

// Cipherer is the standard interface for encryption/decryption used by this package.
// Implementations may encrypt (AES-GCM) or pass-through (no-op).
type Cipherer interface {
	Encrypt(plain string) (string, error)
	Decrypt(token string) (string, error)
	DecryptAndCompare(token string, other string) (bool, error)
}

// GenerateKey generates a cryptographically secure random 32-byte key,
// returned as base64 (no padding).
func GenerateKey() string {
	k := make([]byte, keySize)
	_, _ = io.ReadFull(rand.Reader, k)

	return base64.RawURLEncoding.EncodeToString(k)
}

// New initializes a Cipherer.
//
// If key == "" it returns a NoopCipher (encryption disabled).
//
// Otherwise it initializes AES-GCM with an AES key provided as a string.
//
// It accepts either:
//   - a raw key string whose byte length is exactly 16, 24, or 32, OR
//   - a base64-url (no padding) encoded key (as produced by GenerateKey),
//     and will also accept standard base64 (with or without padding).
func New(key string) (Cipherer, error) {
	if key == "" {
		return NoopCipher{}, nil
	}

	k := []byte(key)

	// If it doesn't look like a raw AES key length, try base64 decode.
	if l := len(k); l != 16 && l != 24 && l != 32 {
		// Try base64url (no padding) first (matches GenerateKey()).
		if decoded, err := base64.RawURLEncoding.DecodeString(key); err == nil {
			k = decoded
		} else if decoded, err := base64.URLEncoding.DecodeString(key); err == nil {
			// Accept padded base64url too.
			k = decoded
		} else if decoded, err := base64.RawStdEncoding.DecodeString(key); err == nil {
			// Accept standard base64 (with/without padding).
			k = decoded
		} else if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
			k = decoded
		}

		// Validate again after potential decode.
		if l := len(k); l != 16 && l != 24 && l != 32 {
			return nil, errors.New("invalid key length: must be 16, 24, or 32 bytes or a base64-encoded")
		}
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Cipher{aead: aead}, nil
}

//

type Cipher struct {
	aead cipher.AEAD
}

func (c *Cipher) Encrypt(plain string) (string, error) {
	out := make([]byte, c.aead.NonceSize()) // nolint: prealloc

	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return "", err
	}

	ct := c.aead.Seal(nil, out, []byte(plain), nil)

	out = append(out, ct...) // nolint: makezero

	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (c *Cipher) Decrypt(token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("token too short")
	}

	nonce, ct := raw[:ns], raw[ns:]

	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(pt), nil
}

func (c *Cipher) DecryptAndCompare(token string, other string) (bool, error) {
	plain, err := c.Decrypt(token)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(plain), []byte(other)) == 1, nil
}
