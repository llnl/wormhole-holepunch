package ledger

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// hostSessionKeyPrefix namespaces host session records. Keys contain a hash, not the handle.
const hostSessionKeyPrefix = "oauthsession.v1."

// hostSessionHandleBytes is the random length of a host session handle (256 bits).
const hostSessionHandleBytes = 32

// ErrSessionUnavailable indicates an unknown, expired, revoked, or malformed host session.
var ErrSessionUnavailable = errors.New("oauth host session not found or expired")

// hostSession binds a captured oauth2-proxy session to the single host it was redeemed on.
type hostSession struct {
	Host         string    `json:"host"`
	ProxySession string    `json:"proxy_session"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ResolveHostSession returns the oauth2-proxy session when handle was issued for host.
// A host mismatch returns ErrBindingMismatch and attempts to revoke the session; a failed
// revocation is logged but does not change the error. Other store failures are wrapped.
func (l *Store) ResolveHostSession(ctx context.Context, handle, host string) (string, error) {
	if !validHostSessionHandle(handle) {
		return "", ErrSessionUnavailable
	}

	key := hostSessionKey(handle)

	var s hostSession
	if err := l.kvStore.Get(ctx, key, &s); err != nil {
		if errors.Is(err, streams.ErrKeyNotFound) {
			return "", ErrSessionUnavailable
		}

		return "", fmt.Errorf("reading oauth host session: %w", err)
	}

	// The bucket isn't guaranteed to evict expired entries immediately.
	if !time.Now().Before(s.ExpiresAt) {
		return "", ErrSessionUnavailable
	}

	if !oauthapi.SameHTTPSAuthority(host, s.Host) {
		ll := logs.FromContext(ctx, l.ll)
		ll.WarnCtx(ctx, "oauth host session rejected: presented on a different host, revoking it")

		if err := l.kvStore.Delete(ctx, key); err != nil {
			ll.WarnCtx(ctx, fmt.Sprintf("failed to revoke misused oauth host session: %s", err))
		}

		return "", ErrBindingMismatch
	}

	return s.ProxySession, nil
}

// issueHostSession stores proxySession for host under a new random handle, returning the
// handle for the host-only session cookie.
func (l *Store) issueHostSession(ctx context.Context, host, proxySession string) (string, error) {
	handle, hash, err := newHostSessionHandle()
	if err != nil {
		return "", err
	}

	rec := hostSession{
		Host:         host,
		ProxySession: proxySession,
		ExpiresAt:    time.Now().Add(l.sessionTTL),
	}

	if err := l.kvStore.CreateWithTTL(ctx, hostSessionKeyPrefix+hash, rec, l.sessionTTL); err != nil {
		return "", fmt.Errorf("failed to store oauth host session: %w", err)
	}

	return handle, nil
}

func newHostSessionHandle() (string, string, error) {
	b := make([]byte, hostSessionHandleBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate host session handle: %w", err)
	}

	handle := base64.RawURLEncoding.EncodeToString(b)

	return handle, base64.RawURLEncoding.EncodeToString(hashBrowserBindingSecret(handle)), nil
}

func hostSessionKey(handle string) string {
	return hostSessionKeyPrefix + base64.RawURLEncoding.EncodeToString(hashBrowserBindingSecret(handle))
}

// validHostSessionHandle checks the encoding and length before a store lookup.
func validHostSessionHandle(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)

	return err == nil && len(b) == hostSessionHandleBytes
}
