package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

const (
	// expSkew provides the maximum allowed skew between a defined
	// expiration and when it will begin enforcement to account for
	// potential differences in timing between components.
	expSkew         = 10 * time.Second
	dummyCiphertext = "00000000-0000-0000-0000-000000000000.000000000000000000000000"
)

type cache struct {
	// Disallowed indicates if the cache is generally valid for use. This is not
	// meant as a replacement for other checks and is most likely associated
	// with invalid tokens.
	Disallowed bool                  `json:"disallowed"`
	Payload    wormhole.TokenPayload `json:"payload"`

	// EncryptedToken provides a (potentially) cryptographically secured token
	// that can be stored/retrieved from the cache. This token can either be a
	// WAT (Wormhole Access Token) or an oauth2 access_token derived from a valid
	// user session. In either case this is target for the ConstantTimeCompare since
	// its a guaranteed value provided by an inbound user request.
	EncryptedToken string `json:"wat"`
	decryptedToken string `json:"-"`

	// EncryptedToken provides a (potentially) cryptographically secured token
	// that can be stored/retrieved from the cache. The Jump Token is the internal
	// (to Wormhole) token that should replace any user provided X-Token header.
	EncryptedJumpToken string `json:"jump_token"`
	decryptedJumpToken string `json:"-"`

	/*
		Both the ParentID and ExternalID support tracking and refreshing subtokens
		by ensuring that any token we cache will have the necessary details required
		to recreate the subtoken associated with the valid community.
	*/

	ParentID   string `json:"parent_id"`
	ExternalID string `json:"external_id"`
}

func (c cache) expired() bool {
	now := time.Now()

	return now.After(c.Payload.Exp.Add(-expSkew))
}

//

// getCache retrieves the token cache from the key/value store based upon the given key.
// Any encrypted values will be automatically decrypted, in addition if the user's request
// token is provided it will be compared against the original cached value. Errors will
// indicate that the request must be rejected. Utilize the boolean to help indicate if a
// cache has been identified or if the token service must be invoked.
func (i internal) getCache(
	ctx context.Context,
	ll logs.Logger,
	key, reqToken string,
) (cache, bool, *errs.StatusError) {
	var cs cache

	// Dummy values used to reduce timing differences on miss/invalid paths.
	dummyToken := i.mustDecrypt(ctx, ll, key, dummyCiphertext)

	err := i.kvStore.Get(ctx, key, &cs)
	if err != nil {
		// Do comparable work on miss.
		if reqToken != "" {
			_ = subtle.ConstantTimeCompare([]byte(dummyToken), []byte(reqToken))
		}

		ll.DebugCtx(ctx, "token cache lookup complete")

		return cache{}, false, nil // cache miss
	}

	// Decrypt before branching so common failure paths do similar work.
	cs.decryptedJumpToken = i.mustDecrypt(ctx, ll, key, cs.EncryptedJumpToken)
	cs.decryptedToken = i.mustDecrypt(ctx, ll, key, cs.EncryptedToken)

	invalid := false

	if cs.Disallowed {
		invalid = true
	} else if cs.expired() {
		_ = i.kvStore.Delete(ctx, key)
		invalid = true
	}

	if reqToken != "" {
		invalid = subtle.ConstantTimeCompare([]byte(cs.decryptedToken), []byte(reqToken)) == 0
	}

	if invalid {
		ll.DebugCtx(ctx, "token cache lookup complete")

		return cache{}, false, errs.SimpleAuthErr(errors.New("invalid credentials"))
	}

	ll.DebugCtx(ctx, "token cache lookup complete")

	return cs, true, nil
}

// storeCache manages the interactions with the key/value store, in addition
// to ensuring any sensitive values are encrypted according to the required
// configuration.
func (i internal) storeCache(
	ctx context.Context,
	ll logs.Logger,
	key string,
	cs cache,
) {
	cs.EncryptedJumpToken = i.mustEncrypt(ctx, ll, cs.decryptedJumpToken)
	cs.EncryptedToken = i.mustEncrypt(ctx, ll, cs.decryptedToken)

	err := i.kvStore.Put(ctx, key, cs)
	if err != nil {
		ll.WarnCtx(
			ctx,
			"unable to cache token response",
			ll.StringArg("error", err.Error()),
		)
	}
}

// storeInvalidCache offers a simple way to store an invalid token in the cache
// and temporarily prevent additional requests to the Token Service.
func (i internal) storeInvalidCache(
	ctx context.Context,
	ll logs.Logger,
	key string,
) {
	i.storeCache(ctx, ll, key, cache{Disallowed: true})
}

func (i internal) mustDecrypt(
	ctx context.Context,
	ll logs.Logger,
	key, token string,
) string {
	if token == "" {
		// Depending on the workflow it's possible we don't
		// have anything to decrypt (e.g., oauth+WAT).
		return ""
	}

	plain, err := i.cipher.Decrypt(token)
	if err != nil {
		ll.WarnCtx(ctx, "corrupted encrypted value: "+err.Error())

		// This would only occur if the cache has been corrupted or
		// the AES was improperly rotated. Deleting the cache is the
		// only reasonable solution.
		_ = i.kvStore.Delete(ctx, key)
	}

	return plain
}

func (i internal) mustEncrypt(
	ctx context.Context,
	ll logs.Logger,
	plain string,
) string {
	if plain == "" {
		// Depending on the workflow it's possible we don't
		// have anything to encrypt (e.g., oauth+WAT).
		return ""
	}

	enc, err := i.cipher.Encrypt(plain)
	if err != nil {
		ll.WarnCtx(ctx, "failed to encrypt: "+err.Error())
	}

	return enc
}
