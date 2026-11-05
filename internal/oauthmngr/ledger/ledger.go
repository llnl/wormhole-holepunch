// Package ledger manages single-use OAuth flows and session handoffs backed by the shared
// KV store. It owns nonce generation, browser proof, binding checks, and atomic transitions.
package ledger

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

var (
	// ErrInvalidRequest indicates the Ledger request was missing or malformed values.
	ErrInvalidRequest = errors.New("invalid ledger request")
	// ErrFlowUnavailable covers a nonce that is unknown, expired, already consumed, or lost
	// a concurrent compare-and-swap. These are intentionally indistinguishable to callers,
	// the ledger logs the specific reason.
	ErrFlowUnavailable = errors.New("oauth flow not found, expired, or already used")
	// ErrBindingMismatch indicates the request did not match the client/host binding
	// established when the nonce was minted. The nonce is burned regardless.
	ErrBindingMismatch = errors.New("request does not match oauth flow binding")
)

type Ledger interface {
	// Capture atomically consumes the nonce at the auth domain, checks the client binding,
	// and stores the oauth2-proxy session cookie against it.
	Capture(ctx context.Context, req oauthapi.CaptureRequest) (oauthapi.CaptureResponse, error)
	// Redeem atomically consumes the captured session at the target sub-domain, checks the
	// client and host binding, and returns the session cookie and target URL.
	Redeem(ctx context.Context, req oauthapi.RedeemRequest) (oauthapi.RedeemResponse, error)
}

// Store mints flows for Holepunch Auth and implements the Ledger consumed by the wasm plugin.
type Store struct {
	authDomain string
	kvStore    streams.KVStore
	ll         logs.Logger
	ttl        time.Duration
}

// New establishes a Store backed by the KV store shared by Holepunch Auth and the ledger
// service. Capture is only accepted at the configured auth domain.
func New(
	kvStore streams.KVStore,
	ll logs.Logger,
	authDomain string,
	nonceTTL time.Duration,
) (*Store, error) {
	switch {
	case authDomain == "":
		return nil, errors.New("user auth URL is required by the ledger")
	case nonceTTL <= 0:
		return nil, errors.New("a positive nonce TTL is required by the ledger")
	}

	return &Store{
		authDomain: authDomain,
		kvStore:    kvStore,
		ll:         ll,
		ttl:        nonceTTL,
	}, nil
}

//

func (l *Store) Capture(ctx context.Context, req oauthapi.CaptureRequest) (oauthapi.CaptureResponse, error) {
	if !oauthapi.ValidNonce(req.Nonce) || req.SessionCookie == "" {
		l.ll.Warnf("ledger capture rejected: malformed request (client_ip=%s)", req.ClientIP)
		return oauthapi.CaptureResponse{}, ErrInvalidRequest
	}

	rec, err := l.transition(ctx, "capture", req.Nonce, flowPending, func(rec *flowRecord) error {
		if err := l.checkBinding(rec, req.ClientIP, req.Authority, l.authDomain); err != nil {
			return err
		}

		rec.State = flowCaptured
		rec.SessionCookie = req.SessionCookie

		return nil
	})
	if err != nil {
		return oauthapi.CaptureResponse{}, err
	}

	scheme := rec.TargetScheme
	if scheme == "" {
		scheme = "https"
	}

	return oauthapi.CaptureResponse{
		TargetSubdomain: rec.TargetSubdomain,
		CallbackURL: fmt.Sprintf(
			"%s://%s%s?nonce=%s",
			scheme,
			rec.TargetSubdomain,
			paths.CallbackPrefix,
			url.QueryEscape(req.Nonce),
		),
	}, nil
}

func (l *Store) Redeem(ctx context.Context, req oauthapi.RedeemRequest) (oauthapi.RedeemResponse, error) {
	if !oauthapi.ValidNonce(req.Nonce) {
		l.ll.Warnf("ledger redeem rejected: malformed request (client_ip=%s)", req.ClientIP)
		return oauthapi.RedeemResponse{}, ErrInvalidRequest
	}

	rec, err := l.transition(ctx, "redeem", req.Nonce, flowCaptured, func(rec *flowRecord) error {
		if err := l.checkBinding(rec, req.ClientIP, req.Authority, rec.TargetSubdomain); err != nil {
			return err
		}

		if req.BindingSecret == "" || len(rec.BrowserBindingHash) != sha256.Size ||
			subtle.ConstantTimeCompare(rec.BrowserBindingHash, hashBrowserBindingSecret(req.BindingSecret)) != 1 {
			l.ll.Warnf("nonce binding failed: browser proof mismatch (client_ip=%s)", req.ClientIP)
			return ErrBindingMismatch
		}

		rec.State = flowBurned
		rec.SessionCookie = ""
		rec.BrowserBindingHash = nil

		return nil
	})
	if err != nil {
		return oauthapi.RedeemResponse{}, err
	}

	// The CAS above already enforces one-time-use, so a failure here is just untidy
	// state left for the bucket TTL to reap - it must not fail the redemption.
	if err := l.kvStore.Delete(ctx, flowKeyPrefix+req.Nonce); err != nil {
		l.ll.Warnf("failed to delete redeemed oauth flow: %s", err)
	}

	return oauthapi.RedeemResponse{
		SessionCookie: rec.SessionCookie,
		TargetURL:     rec.TargetURL,
	}, nil
}

// Mint generates a nonce and browser secret and stores a pending flow bound to the client
// and target sub-domain. Only Holepunch Auth mints flows, via PrepareAuthRedirect.
func (l *Store) Mint(ctx context.Context, req MintRequest) (MintResult, error) {
	secret, bindingHash, err := newBrowserBindingSecret()
	if err != nil {
		return MintResult{}, err
	}

	nonce, err := generateNonce()
	if err != nil {
		return MintResult{}, err
	}

	rec := flowRecord{
		State:              flowPending,
		ClientIP:           req.ClientIP,
		TargetScheme:       req.TargetScheme,
		TargetSubdomain:    req.TargetSubdomain,
		TargetURL:          req.TargetURL,
		BrowserBindingHash: bindingHash,
		CreatedAt:          time.Now(),
	}

	if err := l.kvStore.Put(ctx, flowKeyPrefix+nonce, rec); err != nil {
		return MintResult{}, fmt.Errorf("failed to store nonce: %w", err)
	}

	return MintResult{Nonce: nonce, BindingSecret: secret}, nil
}

func newBrowserBindingSecret() (string, []byte, error) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate browser binding secret: %w", err)
	}

	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	return secret, hashBrowserBindingSecret(secret), nil
}

func hashBrowserBindingSecret(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))

	return hash[:]
}

// transition atomically moves the flow out of the expected state. apply runs against the
// record read at the same revision as the compare-and-swap; if it returns an error the flow
// is burned instead, so a binding failure still consumes the nonce and there is no window
// between "read" and "consume". The record as it was prior to the transition is returned.
func (l *Store) transition(
	ctx context.Context,
	op string,
	nonce string,
	from flowState,
	apply func(*flowRecord) error,
) (flowRecord, error) {
	key := flowKeyPrefix + nonce

	var rec flowRecord

	revision, err := l.kvStore.GetWithRevision(ctx, key, &rec)
	if err != nil {
		l.ll.Warnf("ledger %s rejected: nonce not found", op)
		return flowRecord{}, ErrFlowUnavailable
	}

	// The store isn't guaranteed to evict expired entries immediately, so CreatedAt/ttl
	// remains the source of truth; a failed cleanup delete doesn't fail the call.
	if time.Since(rec.CreatedAt) > l.ttl {
		l.ll.Warnf("ledger %s rejected: nonce expired (age=%v)", op, time.Since(rec.CreatedAt))

		if err := l.kvStore.Delete(ctx, key); err != nil {
			l.ll.Debugf("failed to delete expired oauth flow: %s", err)
		}

		return flowRecord{}, ErrFlowUnavailable
	}

	if rec.State != from {
		l.ll.Warnf("ledger %s rejected: unexpected flow state %q (client_ip=%s)", op, rec.State, rec.ClientIP)
		return flowRecord{}, ErrFlowUnavailable
	}

	original := rec

	applyErr := apply(&rec)
	if applyErr != nil {
		rec = flowRecord{State: flowBurned, CreatedAt: original.CreatedAt}
	}

	if err := l.kvStore.UpdateWithRevision(ctx, key, rec, revision); err != nil {
		l.ll.Warnf("ledger %s rejected: concurrent modification detected", op)
		return flowRecord{}, ErrFlowUnavailable
	}

	if applyErr != nil {
		return flowRecord{}, applyErr
	}

	return original, nil
}

// checkBinding validates the request against the client IP the flow was minted for and the
// authority the current step is required to be made against.
func (l *Store) checkBinding(rec *flowRecord, clientIP, authority, expectedAuthority string) error {
	if rec.ClientIP == "" || rec.ClientIP != clientIP {
		l.ll.Warnf("nonce binding failed: client IP mismatch (expected=%s, got=%s)", rec.ClientIP, clientIP)
		return ErrBindingMismatch
	}

	// Ports are not significant, Envoy's :authority may include one where the route's
	// configured host does not (or vice versa).
	if expectedAuthority == "" || oauthapi.HostOnly(authority) != oauthapi.HostOnly(expectedAuthority) {
		l.ll.Warnf("nonce binding failed: authority mismatch (expected=%s, got=%s)", expectedAuthority, authority)
		return ErrBindingMismatch
	}

	return nil
}

// generateNonce creates a cryptographically secure random nonce with 128-bit entropy.
func generateNonce() (string, error) {
	b := make([]byte, oauthapi.NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
