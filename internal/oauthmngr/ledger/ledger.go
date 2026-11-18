// Package ledger manages single-use OAuth flows and session handoffs in shared KV storage.
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
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

var (
	// ErrInvalidRequest indicates a missing or malformed request value.
	ErrInvalidRequest = errors.New("invalid ledger request")
	// ErrFlowUnavailable indicates an unavailable flow, including a storage read or update failure.
	ErrFlowUnavailable = errors.New("oauth flow not found, expired, or already used")
	// ErrBindingMismatch indicates a client or host binding failure.
	ErrBindingMismatch = errors.New("request does not match oauth flow binding")
)

// Ledger provides the callback operations for an OAuth flow.
type Ledger interface {
	// BeginCapture returns an auth proof and its challenge for a pending flow.
	BeginCapture(ctx context.Context, nonce string) (CaptureStart, error)
	// AuthorizeCapture binds the challenge to the application browser's proof.
	AuthorizeCapture(ctx context.Context, req AuthorizeRequest) error
	// Capture stores the auth-domain session after checking its proof.
	Capture(ctx context.Context, req CaptureRequest) (CaptureResponse, error)
	// Redeem consumes the flow and returns a host session handle and target URL.
	Redeem(ctx context.Context, req RedeemRequest) (RedeemResponse, error)
}

// Store mints flows for Holepunch Auth, implements Ledger for the callback, and resolves the
// host sessions issued by Redeem. Flows and host sessions share one KV bucket under separate
// key prefixes, each carrying its own per-key TTL.
type Store struct {
	authDomain string
	kvStore    streams.KVStore
	ll         logs.Logger
	ttl        time.Duration
	sessionTTL time.Duration
}

// New creates a Store using the shared KV store. Capture is restricted to authDomain, nonceTTL
// bounds a flow and sessionTTL a redeemed host session; both must be at least one second, the
// smallest per-key TTL NATS supports.
func New(
	kvStore streams.KVStore,
	ll logs.Logger,
	authDomain string,
	nonceTTL time.Duration,
	sessionTTL time.Duration,
) (*Store, error) {
	switch {
	case authDomain == "":
		return nil, errors.New("user auth URL is required by the ledger")
	case nonceTTL < minKeyTTL:
		return nil, fmt.Errorf("a nonce TTL of at least %s is required by the ledger", minKeyTTL)
	case sessionTTL < minKeyTTL:
		return nil, fmt.Errorf("a session TTL of at least %s is required by the ledger", minKeyTTL)
	}

	return &Store{
		authDomain: authDomain,
		kvStore:    kvStore,
		ll:         ll,
		ttl:        nonceTTL,
		sessionTTL: sessionTTL,
	}, nil
}

// BeginCapture returns a proof and its hash as a challenge for a pending flow.
func (l *Store) BeginCapture(ctx context.Context, nonce string) (CaptureStart, error) {
	if !oauthapi.ValidNonce(nonce) {
		return CaptureStart{}, ErrInvalidRequest
	}

	rec, _, err := l.readFlow(ctx, "begin capture", nonce, flowPending)
	if err != nil {
		return CaptureStart{}, err
	}

	proof, hash, err := newBrowserBindingSecret()
	if err != nil {
		return CaptureStart{}, err
	}

	return CaptureStart{
		TargetAuthority: rec.TargetSubdomain,
		AuthProof:       proof,
		Challenge:       base64.RawURLEncoding.EncodeToString(hash),
	}, nil
}

// AuthorizeCapture binds the auth challenge to the application browser proof.
func (l *Store) AuthorizeCapture(ctx context.Context, req AuthorizeRequest) error {
	hash, err := base64.RawURLEncoding.Strict().DecodeString(req.Challenge)
	if !oauthapi.ValidNonce(req.Nonce) || err != nil || len(hash) != sha256.Size {
		return ErrInvalidRequest
	}

	_, err = l.transition(ctx, "authorize capture", req.Nonce, flowPending, func(rec *flowRecord) error {
		if !oauthapi.SameHTTPSAuthority(req.Authority, rec.TargetSubdomain) {
			l.ll.Warnf("ledger authorize capture rejected: requested on %q, but the flow targets %q",
				req.Authority, rec.TargetSubdomain)

			return ErrBindingMismatch
		}

		if !matchesBinding(req.BindingSecret, rec.BrowserBindingHash) {
			l.ll.Warn("ledger authorize capture rejected: binding cookie does not match the browser that started the flow")
			return ErrBindingMismatch
		}

		rec.AuthProofHash = hash
		rec.State = flowAuthorized

		return nil
	})

	return err
}

// Capture stores the session only after both browser proofs have been verified.
func (l *Store) Capture(ctx context.Context, req CaptureRequest) (CaptureResponse, error) {
	if !oauthapi.ValidNonce(req.Nonce) || req.SessionCookie == "" || req.AuthProof == "" {
		l.ll.Warn("ledger capture rejected: malformed request")
		return CaptureResponse{}, ErrInvalidRequest
	}

	code, err := generateNonce()
	if err != nil {
		return CaptureResponse{}, err
	}

	rec, err := l.transition(ctx, "capture", req.Nonce, flowAuthorized, func(rec *flowRecord) error {
		if !oauthapi.SameHTTPSAuthority(req.Authority, l.authDomain) {
			l.ll.Warnf("ledger capture rejected: requested on %q, not the auth host %q", req.Authority, l.authDomain)

			return ErrBindingMismatch
		}

		if !matchesBinding(req.AuthProof, rec.AuthProofHash) {
			l.ll.Warn("ledger capture rejected: auth proof cookie does not match the authorized challenge " +
				"(the proof page was reloaded or opened in another tab)")

			return ErrBindingMismatch
		}

		rec.State = flowCaptured
		rec.SessionCookie = req.SessionCookie
		rec.AuthProofHash = nil
		rec.RedeemCodeHash = hashBrowserBindingSecret(code)

		return nil
	})
	if err != nil {
		return CaptureResponse{}, err
	}

	return CaptureResponse{
		TargetSubdomain: rec.TargetSubdomain,
		RedeemCode:      code,
	}, nil
}

// Redeem consumes a captured flow after validating its host, browser proof, and code, then
// issues a host session. The response contains the handle, not the oauth2-proxy session.
func (l *Store) Redeem(ctx context.Context, req RedeemRequest) (RedeemResponse, error) {
	if !oauthapi.ValidNonce(req.Nonce) || !oauthapi.ValidNonce(req.Code) {
		l.ll.Warn("ledger redeem rejected: malformed request")
		return RedeemResponse{}, ErrInvalidRequest
	}

	rec, err := l.transition(ctx, "redeem", req.Nonce, flowCaptured, func(rec *flowRecord) error {
		if !oauthapi.SameHTTPSAuthority(req.Authority, rec.TargetSubdomain) {
			l.ll.Warnf("ledger redeem rejected: requested on %q, but the flow targets %q",
				req.Authority, rec.TargetSubdomain)

			return ErrBindingMismatch
		}

		if !matchesBinding(req.BindingSecret, rec.BrowserBindingHash) {
			l.ll.Warn("ledger redeem rejected: binding cookie does not match the browser that started the flow")
			return ErrBindingMismatch
		}

		if !matchesBinding(req.Code, rec.RedeemCodeHash) {
			l.ll.Warn("ledger redeem rejected: redemption code does not match the one issued at capture")
			return ErrBindingMismatch
		}

		rec.State = flowBurned
		rec.SessionCookie = ""
		rec.BrowserBindingHash = nil
		rec.RedeemCodeHash = nil

		return nil
	})
	if err != nil {
		return RedeemResponse{}, err
	}

	// The CAS above already enforces one-time-use, so a failure here is just untidy
	// state left for the bucket TTL to reap - it must not fail the redemption.
	if err := l.kvStore.Delete(ctx, flowKeyPrefix+req.Nonce); err != nil {
		l.ll.Warnf("failed to delete redeemed oauth flow: %s", err)
	}

	// The flow is already consumed, so a failure here requires the browser to start over.
	handle, err := l.issueHostSession(ctx, rec.TargetSubdomain, rec.SessionCookie)
	if err != nil {
		return RedeemResponse{}, err
	}

	return RedeemResponse{
		SessionHandle: handle,
		TargetURL:     rec.TargetURL,
	}, nil
}

// Mint stores a pending flow bound to the supplied target and returns its nonce and browser secret.
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
		TargetScheme:       req.TargetScheme,
		TargetSubdomain:    req.TargetSubdomain,
		TargetURL:          boundTargetURL(req.TargetURL),
		BrowserBindingHash: bindingHash,
		CreatedAt:          time.Now(),
	}

	// Create never overwrites, so a colliding nonce can't replace another browser's flow.
	if err := l.kvStore.CreateWithTTL(ctx, flowKeyPrefix+nonce, rec, l.ttl); err != nil {
		return MintResult{}, fmt.Errorf("failed to store nonce: %w", err)
	}

	return MintResult{Nonce: nonce, BindingSecret: secret}, nil
}

// maxTargetURLLen bounds the client-controlled target URL stored with every unauthenticated
// flow, so oversized request paths cannot inflate stored records.
const maxTargetURLLen = 2048

// boundTargetURL returns raw if it fits maxTargetURLLen, otherwise it drops the query and
// fragment and then the path. An empty result makes the callback fall back to "/".
func boundTargetURL(raw string) string {
	if len(raw) <= maxTargetURLLen {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	if s := u.String(); len(s) <= maxTargetURLLen {
		return s
	}

	u.Path, u.RawPath = "/", ""
	if s := u.String(); len(s) <= maxTargetURLLen {
		return s
	}

	return ""
}

// transition applies a state change with revision-based compare-and-swap. On an apply error,
// it attempts to burn the flow. On success it returns the record read before the transition.
func (l *Store) transition(
	ctx context.Context,
	op string,
	nonce string,
	from flowState,
	apply func(*flowRecord) error,
) (flowRecord, error) {
	rec, revision, err := l.readFlow(ctx, op, nonce, from)
	if err != nil {
		return flowRecord{}, err
	}

	key := flowKeyPrefix + nonce

	original := rec

	applyErr := apply(&rec)
	if applyErr != nil {
		rec = flowRecord{State: flowBurned, CreatedAt: original.CreatedAt}
	}

	// Carry the remaining flow lifetime; a plain update would use the bucket TTL.
	if err := l.kvStore.UpdateWithRevisionTTL(ctx, key, rec, revision, l.remainingTTL(original.CreatedAt)); err != nil {
		// Usually a lost race against a concurrent request for the same flow; the store's
		// error says when it is something else, such as per-key TTLs being unsupported.
		l.ll.Warnf("ledger %s rejected: flow update failed (concurrent modification or store error): %s", op, err)
		return flowRecord{}, ErrFlowUnavailable
	}

	if applyErr != nil {
		return flowRecord{}, applyErr
	}

	return original, nil
}

func (l *Store) readFlow(ctx context.Context, op, nonce string, from flowState) (flowRecord, uint64, error) {
	key := flowKeyPrefix + nonce

	var rec flowRecord

	revision, err := l.kvStore.GetWithRevision(ctx, key, &rec)
	if err != nil {
		l.ll.Warnf("ledger %s rejected: flow not found (expired, already redeemed, or unknown): %s", op, err)
		return flowRecord{}, 0, ErrFlowUnavailable
	}

	// The store isn't guaranteed to evict expired entries immediately, so CreatedAt/ttl
	// remains the source of truth; a failed cleanup delete doesn't fail the call.
	if time.Since(rec.CreatedAt) > l.ttl {
		l.ll.Warnf("ledger %s rejected: nonce expired (age=%v)", op, time.Since(rec.CreatedAt))

		if err := l.kvStore.Delete(ctx, key); err != nil {
			l.ll.Debugf("failed to delete expired oauth flow: %s", err)
		}

		return flowRecord{}, 0, ErrFlowUnavailable
	}

	if rec.State != from {
		l.ll.Warnf("ledger %s rejected: unexpected flow state %q", op, rec.State)
		return flowRecord{}, 0, ErrFlowUnavailable
	}

	return rec, revision, nil
}

// remainingTTL returns how long a flow created at createdAt has left, never below minKeyTTL.
// The floor also covers flows that expire between the read and update.
func (l *Store) remainingTTL(createdAt time.Time) time.Duration {
	return max(l.ttl-time.Since(createdAt), minKeyTTL)
}

// generateNonce returns a cryptographically random 128-bit nonce.
func generateNonce() (string, error) {
	b := make([]byte, oauthapi.NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
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

func matchesBinding(secret string, expected []byte) bool {
	return secret != "" && len(expected) == sha256.Size &&
		subtle.ConstantTimeCompare(expected, hashBrowserBindingSecret(secret)) == 1
}
