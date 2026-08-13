package oauthmngr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
)

const (
	nonceBytes       = 16
	nonceKeyPrefix   = "oauth:nonce:"
	sessionKeyPrefix = "oauth:session:"
)

// errNonceNotFound and errSessionNotFound cover both a missing key and one that's
// expired per CreatedAt/ttl - the KV store isn't guaranteed to evict expired entries
// immediately, so expiry isn't treated as distinct from absence.
var (
	errNonceNotFound   = errors.New("nonce not found or expired")
	errSessionNotFound = errors.New("session not found or expired")
)

// nonceData stores the metadata associated with a nonce for validation
type nonceData struct {
	TargetURL       string    `json:"target_url"`
	ClientIP        string    `json:"client_ip"`
	TargetSubdomain string    `json:"target_subdomain"`
	CreatedAt       time.Time `json:"created_at"`
	Used            bool      `json:"used"`
}

// sessionData stores the oauth2-proxy session cookie captured at the auth domain
type sessionData struct {
	SessionCookie string    `json:"session_cookie"`
	NonceData     nonceData `json:"nonce_data"`
	CreatedAt     time.Time `json:"created_at"`
	Used          bool      `json:"used"`
}

// generateNonce creates a cryptographically secure random nonce with at least 128-bit entropy.
func generateNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// storeNonce stores nonce data in the KV store, keyed by nonce.
func storeNonce(ctx context.Context, kvStore streams.KVStore, nonce string, data nonceData) error {
	key := nonceKeyPrefix + nonce
	if err := kvStore.Put(ctx, key, data); err != nil {
		return fmt.Errorf("failed to store nonce: %w", err)
	}

	return nil
}

// retrieveAndConsumeNonce retrieves nonce data and marks it as used (single-use enforcement).
// Returns an error if the nonce doesn't exist, has already been used, or has expired.
// Uses atomic compare-and-swap to prevent TOCTOU race conditions.
func retrieveAndConsumeNonce(
	ctx context.Context, kvStore streams.KVStore, ll logs.Logger, nonce string, ttl int,
) (nonceData, error) {
	key := nonceKeyPrefix + nonce

	var data nonceData

	// Get the nonce with its revision number for atomic update
	revision, err := kvStore.GetWithRevision(ctx, key, &data)
	if err != nil {
		ll.Warn("nonce validation failed: nonce not found")
		return nonceData{}, errNonceNotFound
	}

	if data.Used {
		ll.Warnf("nonce validation failed: nonce already used (client_ip=%s)", data.ClientIP)
		return nonceData{}, errors.New("nonce already used")
	}

	// The store isn't guaranteed to evict expired entries immediately, so CreatedAt/ttl
	// remains the source of truth. This isn't an error - it's treated like a missing
	// entry: logged at Debug, and a failed cleanup delete doesn't fail the call.
	if time.Since(data.CreatedAt) > time.Duration(ttl)*time.Second {
		ll.Debugf("nonce expired (age=%v)", time.Since(data.CreatedAt))

		if err := kvStore.Delete(ctx, key); err != nil {
			ll.Debugf("failed to delete expired nonce: %s", err)
		}

		return nonceData{}, errNonceNotFound
	}

	// Atomically mark as used only if revision hasn't changed (prevents race condition)
	data.Used = true
	if err := kvStore.UpdateWithRevision(ctx, key, data, revision); err != nil {
		ll.Warn("nonce validation failed: concurrent modification detected")
		return nonceData{}, errors.New("nonce already used")
	}

	return data, nil
}

// validateNonceBinding validates that the nonce is bound to the correct client characteristics.
func validateNonceBinding(ll logs.Logger, stored nonceData, details requests.RequestDetails) error {
	if stored.ClientIP != details.ClientIP {
		ll.Warnf("nonce validation failed: client IP mismatch (expected=%s, got=%s)",
			stored.ClientIP, details.ClientIP)

		return errors.New("client IP does not match nonce binding")
	}

	if stored.TargetSubdomain != details.Host {
		ll.Warnf("nonce validation failed: subdomain mismatch (expected=%s, got=%s)",
			stored.TargetSubdomain, details.Host)

		return errors.New("target subdomain does not match nonce binding")
	}

	return nil
}

// storeSessionData stores the captured session cookie with nonce data
func storeSessionData(ctx context.Context, kvStore streams.KVStore, nonce string, data sessionData) error {
	key := sessionKeyPrefix + nonce

	if err := kvStore.Put(ctx, key, data); err != nil {
		return fmt.Errorf("failed to store session data: %w", err)
	}

	return nil
}

// retrieveAndDeleteSessionData retrieves session data and marks it used (single-use
// enforcement), erroring if it doesn't exist, was already used, or expired. Uses
// compare-and-swap to prevent TOCTOU races, mirroring retrieveAndConsumeNonce; the key
// is then deleted as best-effort cleanup, though the CAS is what enforces one-time-use.
func retrieveAndDeleteSessionData(
	ctx context.Context, kvStore streams.KVStore, ll logs.Logger, nonce string, ttl int,
) (sessionData, error) {
	key := sessionKeyPrefix + nonce

	var data sessionData

	// Get the session with its revision number for atomic update
	revision, err := kvStore.GetWithRevision(ctx, key, &data)
	if err != nil {
		ll.Warn("session retrieval failed: session not found")
		return sessionData{}, errSessionNotFound
	}

	if data.Used {
		ll.Warn("session retrieval failed: session already used")
		return sessionData{}, errors.New("session already used")
	}

	// The store isn't guaranteed to evict expired entries immediately, so CreatedAt/ttl
	// remains the source of truth. This isn't an error - it's treated like a missing
	// entry: logged at Debug, and a failed cleanup delete doesn't fail the call.
	if time.Since(data.CreatedAt) > time.Duration(ttl)*time.Second {
		ll.Debugf("session expired (age=%v)", time.Since(data.CreatedAt))

		if err := kvStore.Delete(ctx, key); err != nil {
			ll.Debugf("failed to delete expired session: %s", err)
		}

		return sessionData{}, errSessionNotFound
	}

	// Atomically mark as used only if revision hasn't changed (prevents race condition)
	data.Used = true
	if err := kvStore.UpdateWithRevision(ctx, key, data, revision); err != nil {
		ll.Warn("session retrieval failed: concurrent modification detected")
		return sessionData{}, errors.New("session already used")
	}

	// The CAS above already enforces one-time-use, so a failure here is just untidy
	// state left for the bucket TTL to reap - it must not fail the redemption.
	if err := kvStore.Delete(ctx, key); err != nil {
		ll.Warnf("failed to delete consumed session data: %s", err)
	}

	return data, nil
}

// cleanupNonce removes a nonce from the store
func cleanupNonce(ctx context.Context, kvStore streams.KVStore, nonce string) {
	key := nonceKeyPrefix + nonce
	_ = kvStore.Delete(ctx, key)
}
