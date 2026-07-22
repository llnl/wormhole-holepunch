package aescipher

import "crypto/subtle"

// NoopCipher is a pass-through implementation of Cipherer.
// It performs no encryption and returns unmodified values.
type NoopCipher struct{}

func (NoopCipher) Encrypt(plain string) (string, error) { return plain, nil }

func (NoopCipher) Decrypt(token string) (string, error) { return token, nil }

func (NoopCipher) DecryptAndCompare(token string, other string) (bool, error) {
	// Keep constant-time semantics where possible.
	if len(token) != len(other) {
		_ = subtle.ConstantTimeCompare([]byte(token), []byte(token))

		return false, nil
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(other)) == 1, nil
}
