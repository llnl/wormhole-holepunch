// Package token maintains interactions with the Token Service for the
// purposes of authentication.
package token

import (
	"context"
	"net/url"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/aescipher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

type AuthResponse struct {
	SetHeaders    map[string]string
	RemoveHeaders []string
}

type Authenticator interface {
	// RequestHeader authenticates a given request using the user-provided
	// token in the Authorization header. The newly issued JWT is included
	// in the request header.
	RequestHeader(
		ctx context.Context,
		ll logs.Logger,
		req requests.RequestDetails,
	) (wormhole.TokenContext, AuthResponse, *errs.StatusError)

	// SubtokenFlow realizes support for subtoken (community) process for
	// a previously authenticated and authorized user request.
	SubtokenFlow(
		ctx context.Context,
		ll logs.Logger,
		req requests.RequestDetails,
		tknCtx wormhole.TokenContext,
	) (string, *errs.StatusError)

	// InvalidateToken sets the token cache to prevent usage.
	InvalidateToken(ctx context.Context, tokenID string)

	// RemoveSubtoken attempts to remove a given subtoken (based upon the parent +
	// external IDs) from the cache as well as invalidating the token itself.
	RemoveSubtoken(ctx context.Context, parentID, externalID, tokenID string)
}

type internal struct {
	cipher  aescipher.Cipherer
	client  requests.Client
	kvStore streams.KVStore
	ll      logs.Logger
	// oauth authenticates requests lacking a WAT through session cookies, and starts a new
	// OAuth flow when they are missing or no longer valid.
	oauth            oauthmngr.Validator
	oauthExchangeURL string
	tokenExchangeURL string
	tokenSvcArgs     args.TokenService
	subtokenReqURL   string
	validator        rules.Validator
}

// Initialize configures the internal authenticator with the provided settings. Requests
// lacking a WAT are authenticated through the oauth Validator, use oauthmngr.Disabled when
// OAuth is not supported.
func Initialize(
	cipher aescipher.Cipherer,
	kvStore streams.KVStore,
	ll logs.Logger,
	tokenSvcArgs args.TokenService,
	oauth oauthmngr.Validator,
) Authenticator {
	tokenURL, _ := url.Parse(tokenSvcArgs.TokenHost)

	i := internal{
		cipher:           cipher,
		client:           requests.DefaultClient(ll),
		kvStore:          kvStore,
		ll:               ll,
		oauth:            oauth,
		oauthExchangeURL: tokenURL.JoinPath(tokenSvcArgs.OauthExchangePath).String(),
		tokenExchangeURL: tokenURL.JoinPath(tokenSvcArgs.TokenExchangePath).String(),
		tokenSvcArgs:     tokenSvcArgs,
		subtokenReqURL:   tokenURL.JoinPath(tokenSvcArgs.SubtokenPath).String(),
		validator:        rules.NewValidator(),
	}

	return i
}

//

func (i internal) RequestHeader(
	ctx context.Context,
	ll logs.Logger,
	req requests.RequestDetails,
) (wormhole.TokenContext, AuthResponse, *errs.StatusError) {
	ctx, endSpan := ll.StartSpan(ctx, "RequestHeader")
	defer endSpan()

	var jwt string

	var sErr *errs.StatusError

	tknCtx, found, err := i.retrieveWAT(req)
	if err != nil {
		return wormhole.TokenContext{}, AuthResponse{}, errs.SimpleBadReqErr(err)
	}

	var (
		payload wormhole.TokenPayload
		session *oauthmngr.Result
	)

	if found {
		payload, jwt, sErr = i.wormholeAccessTokenFlow(ctx, ll, tknCtx.WAT, tknCtx.TokenID)
	} else {
		payload, jwt, session, sErr = i.oauthFlow(ctx, ll, req)
	}

	if sErr != nil {
		return wormhole.TokenContext{}, AuthResponse{}, sErr
	}

	tknCtx.Payload = payload

	ll.InfoCtx(ctx, tknCtx.Payload.Username+" successfully authenticated")

	resp := AuthResponse{
		SetHeaders:    i.setHeaders(jwt, req),
		RemoveHeaders: []string{},
	}

	// Session cookies must never reach the upstream, forward the Cookie header with them
	// stripped (or drop it entirely when nothing else remains).
	if session != nil {
		if session.CookieHeader == "" {
			resp.RemoveHeaders = append(resp.RemoveHeaders, keys.CookieHeader)
		} else {
			resp.SetHeaders[keys.CookieHeader] = session.CookieHeader
		}
	}

	return tknCtx, resp, nil
}

func (i internal) InvalidateToken(ctx context.Context, tokenID string) {
	ctx, endSpan := i.ll.StartSpan(ctx, "RemoveToken")
	defer endSpan()

	key := keys.WormholeAccessToken(tokenID)

	err := i.kvStore.Put(ctx, key, cache{Disallowed: true})
	if err != nil {
		i.ll.InfoCtx(ctx, "failed to disallow token from cache "+key+": "+err.Error())
	} else {
		i.ll.DebugCtx(ctx, "successfully removed token from cache: "+key)
	}
}

func (i internal) RemoveSubtoken(ctx context.Context, parentID, externalID, tokenID string) {
	ctx, endSpan := i.ll.StartSpan(ctx, "RemoveSubtoken")
	defer endSpan()

	// Invalid the token itself in the cache.
	i.InvalidateToken(ctx, tokenID)

	key := keys.WormholeAccessSubtoken(parentID, externalID)

	err := i.kvStore.Delete(ctx, key)
	if err != nil {
		i.ll.InfoCtx(ctx, "failed to remove subtoken from cache "+key+": "+err.Error())
	} else {
		i.ll.DebugCtx(ctx, "successfully removed subtoken from cache: "+key)
	}
}

//

func (i internal) setHeaders(jwt string, req requests.RequestDetails) map[string]string {
	defaultHeaders := map[string]string{
		// The user's initial authentication token should always be overwritten
		// with the new and more limited scoped JWT.
		i.tokenSvcArgs.TokenHeader: jwt,
		keys.RouteIDHeader:         req.RouteID,
	}

	if req.CommunityID != "" {
		defaultHeaders[keys.CommunityHeader] = req.CommunityID
	}

	return defaultHeaders
}
