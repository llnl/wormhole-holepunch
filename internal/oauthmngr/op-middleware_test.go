package oauthmngr

/*
import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

//

func Test_newOauth2ProxyMiddlewareManager(t *testing.T) {
	t.Run("creates manager with valid configuration", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		ll := logs.NewNopLogger()
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			AuthDomain:       "auth.example.com",
			CookieName:       "_wormhole_session",
			CookieMaxAge:     43200,
			NonceTTL:         300,
			ValidateTokens:   true,
		}

		manager, err := newOauth2ProxyMiddlewareManager(kvStore, ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, oauthArgs.ProxyUpstreamURL, manager.proxyUpstreamURL)
		assert.Equal(t, oauthArgs.AuthDomain, manager.authDomain)
		assert.Equal(t, oauthArgs.CookieName, manager.cookieName)
		assert.Equal(t, oauthArgs.CookieMaxAge, manager.cookieMaxAge)
		assert.Equal(t, oauthArgs.NonceTTL, manager.nonceTTL)
		assert.Equal(t, oauthArgs.ValidateTokens, manager.validateTokens)
	})

	t.Run("returns error when proxy upstream URL is missing", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		ll := logs.NewNopLogger()
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "",
			AuthDomain:       "auth.example.com",
		}

		manager, err := newOauth2ProxyMiddlewareManager(kvStore, ll, oauthArgs)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "oauth2-proxy upstream URL is required")
		assert.Nil(t, manager)
	})

	t.Run("returns error when auth domain is missing", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		ll := logs.NewNopLogger()
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			AuthDomain:       "",
		}

		manager, err := newOauth2ProxyMiddlewareManager(kvStore, ll, oauthArgs)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth domain is required")
		assert.Nil(t, manager)
	})
}

//

func Test_oauth2ProxyMiddlewareManager_ExpandSources(t *testing.T) {
	t.Run("adds oauth2-proxy and callback routes", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://auth.example.com/api"),
				Destination: newURLString("http://backend:8080"),
				CommunityID: "comm1",
			},
			{
				ID:          "route2",
				Source:      newURLString("https://app.example.com/v1"),
				Destination: newURLString("http://backend:8080"),
				CommunityID: "comm1",
			},
		}

		expanded := manager.ExpandSources(rawSources)

		assert.GreaterOrEqual(t, len(expanded), 4)
	})

	t.Run("adds oauth2-proxy route only for auth domain", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://auth.example.com/api"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		var oauth2ProxyRouteFound bool
		for _, route := range expanded {
			if route.ID == "route1-oauth2-proxy" {
				oauth2ProxyRouteFound = true
				assert.Contains(t, route.Source.Raw, "auth.example.com")
				assert.Contains(t, route.Source.Raw, "/-/wormhole/oauth2")
			}
		}

		assert.True(t, oauth2ProxyRouteFound, "oauth2-proxy route should be added for auth domain")
	})

	t.Run("adds callback route for all domains", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		var callbackRouteFound bool
		for _, route := range expanded {
			if route.ID == "route1-oauth-callback" {
				callbackRouteFound = true
				assert.Contains(t, route.Source.Raw, "app.example.com")
				assert.Contains(t, route.Source.Raw, "/-/wormhole/oauthmngr")
			}
		}

		assert.True(t, callbackRouteFound, "callback route should be added")
	})

	t.Run("deduplicates routes for same host", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
			},
			{
				ID:          "route2",
				Source:      newURLString("https://app.example.com/v1"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		callbackCount := 0
		for _, route := range expanded {
			if route.ID == "route1-oauth-callback" || route.ID == "route2-oauth-callback" {
				callbackCount++
			}
		}

		assert.Equal(t, 1, callbackCount, "should only have one callback route per host")
	})

	t.Run("handles sources with nil URL", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("invalid://"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		assert.Len(t, expanded, 1, "should only have original route")
	})
}

//

func Test_oauth2ProxyMiddlewareManager_EstablishPreAuthFunc(t *testing.T) {
	t.Run("skips auth for oauth2-proxy endpoints on auth domain", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			authDomain: "auth.example.com",
		}

		preAuthFunc := manager.EstablishPreAuthFunc(wormhole.RawSource{})
		details := requests.RequestDetails{
			Host: "auth.example.com",
			Path: "/-/wormhole/oauth2/start",
		}

		skip, err := preAuthFunc(details)

		assert.True(t, skip)
		assert.Nil(t, err)
	})

	t.Run("returns error for oauth2-proxy endpoints on non-auth domain", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			authDomain: "auth.example.com",
		}

		preAuthFunc := manager.EstablishPreAuthFunc(wormhole.RawSource{})
		details := requests.RequestDetails{
			Host: "app.example.com",
			Path: "/-/wormhole/oauth2/start",
		}

		skip, err := preAuthFunc(details)

		assert.False(t, skip)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "Authentication service not available on this domain")
	})

	t.Run("skips auth for callback endpoints on any domain", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			authDomain: "auth.example.com",
		}

		preAuthFunc := manager.EstablishPreAuthFunc(wormhole.RawSource{})
		details := requests.RequestDetails{
			Host: "app.example.com",
			Path: "/-/wormhole/oauthmngr?nonce=abc",
		}

		skip, err := preAuthFunc(details)

		assert.True(t, skip)
		assert.Nil(t, err)
	})

	t.Run("does not skip auth for regular endpoints", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			authDomain: "auth.example.com",
		}

		preAuthFunc := manager.EstablishPreAuthFunc(wormhole.RawSource{})
		details := requests.RequestDetails{
			Host: "app.example.com",
			Path: "/api/v1/users",
		}

		skip, err := preAuthFunc(details)

		assert.False(t, skip)
		assert.Nil(t, err)
	})
}

//

func Test_oauth2ProxyMiddlewareManager_PrepareAuthRedirect(t *testing.T) {
	t.Run("generates nonce and creates redirect URL", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			kvStore:          kvStore,
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
			nonceTTL:         300,
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "https",
			Headers: map[string]string{
				"x-forwarded-for": "192.168.1.1",
			},
		}
		proposedRedirect := "https://app.example.com/dashboard"

		redirectURL, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
		assert.Contains(t, redirectURL, "https://auth.example.com/-/wormhole/oauth2/start")
		assert.Contains(t, redirectURL, "rd=")
	})

	t.Run("stores nonce data in KV store", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			kvStore:          kvStore,
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
			nonceTTL:         300,
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "https",
			Headers: map[string]string{
				"x-forwarded-for": "192.168.1.1",
			},
		}
		proposedRedirect := "https://app.example.com/dashboard"

		_, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
	})

	t.Run("defaults to https when scheme is empty", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		manager := &oauth2ProxyMiddlewareManager{
			ll:               logs.NewNopLogger(),
			kvStore:          kvStore,
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			authDomain:       "auth.example.com",
			nonceTTL:         300,
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "",
			Headers: map[string]string{
				"x-forwarded-for": "192.168.1.1",
			},
		}
		proposedRedirect := "https://app.example.com/dashboard"

		redirectURL, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
		assert.Contains(t, redirectURL, "https://")
	})
}

//

func Test_oauth2ProxyMiddlewareManager_RedirectHandler(t *testing.T) {
	t.Run("returns error when nonce parameter is missing", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			authDomain: "auth.example.com",
		}

		ctx := context.Background()
		details := requests.RequestDetails{
			Path: "/-/wormhole/oauthmngr",
		}

		cookie, err := manager.RedirectHandler(ctx, details)

		assert.Nil(t, cookie)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "missing nonce parameter")
	})

	t.Run("handles auth domain callback flow", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			kvStore:    kvStore,
			authDomain: "auth.example.com",
			nonceTTL:   300,
		}

		ctx := context.Background()
		nonce := "test-nonce-123"
		nonceStore := nonceData{
			TargetURL:       "https://app.example.com/dashboard",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
			CreatedAt:       time.Now(),
			Used:            false,
		}
		err := storeNonce(ctx, kvStore, nonce, nonceStore, 300)
		require.NoError(t, err)

		details := requests.RequestDetails{
			Host: "auth.example.com",
			Path: "/-/wormhole/oauthmngr?nonce=" + nonce,
			Headers: map[string]string{
				"cookie": "session-cookie-value",
			},
		}

		cookie, err := manager.RedirectHandler(ctx, details)

		assert.Nil(t, cookie)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "app.example.com")
	})

	t.Run("handles subdomain callback flow", func(t *testing.T) {
		kvStore := streams.NewInMemKV()
		manager := &oauth2ProxyMiddlewareManager{
			ll:           logs.NewNopLogger(),
			kvStore:      kvStore,
			authDomain:   "auth.example.com",
			cookieName:   "_wormhole_session",
			cookieMaxAge: 43200,
			nonceTTL:     300,
		}

		ctx := context.Background()
		nonce := "test-nonce-456"
		sessData := sessionData{
			SessionCookie: "session-value-xyz",
			NonceData: nonceData{
				TargetURL:       "https://app.example.com/dashboard",
				ClientIP:        "192.168.1.1",
				TargetSubdomain: "app.example.com",
				CreatedAt:       time.Now(),
			},
			CreatedAt: time.Now(),
		}
		err := storeSessionData(ctx, kvStore, nonce, sessData, 300)
		require.NoError(t, err)

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Path:   "/-/wormhole/oauthmngr?nonce=" + nonce,
			Scheme: "https",
			Headers: map[string]string{
				"x-forwarded-for": "192.168.1.1",
			},
		}

		cookie, err := manager.RedirectHandler(ctx, details)

		require.NotNil(t, cookie)
		assert.Equal(t, "_wormhole_session", cookie.Name)
		assert.Equal(t, "session-value-xyz", cookie.Value)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "https://app.example.com/dashboard")
	})
}

//

func Test_oauth2ProxyMiddlewareManager_ValidateCookies(t *testing.T) {
	t.Run("validates cookie with configured name", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_wormhole_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "_wormhole_session", Value: "session-token-123"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "session-token-123", result.AccessToken)
	})

	t.Run("returns error when session cookie not found", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_wormhole_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "other_cookie", Value: "other-value"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "session cookie not found")
		assert.Equal(t, "", result.AccessToken)
	})

	t.Run("handles empty cookies slice", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_wormhole_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.NotNil(t, err)
		assert.Equal(t, "", result.AccessToken)
	})

	t.Run("finds correct cookie among multiple cookies", func(t *testing.T) {
		manager := &oauth2ProxyMiddlewareManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_wormhole_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "cookie1", Value: "value1"},
			{Name: "_wormhole_session", Value: "target-token"},
			{Name: "cookie2", Value: "value2"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "target-token", result.AccessToken)
	})
}
*/
