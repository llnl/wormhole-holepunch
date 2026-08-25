package oauthmngr

/*
import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

//

func Test_newOauth2ProxyReverseManager(t *testing.T) {
	t.Run("creates manager with valid configuration", func(t *testing.T) {
		ll := logs.NewNopLogger()
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
			CookieName:       "_wormhole_session",
		}

		manager, err := newOauth2ProxyReverseManager(ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, oauthArgs.ProxyUpstreamURL, manager.proxyUpstreamURL)
		assert.Equal(t, oauthArgs.CookieName, manager.cookieName)
	})

	t.Run("returns error when proxy upstream URL is missing", func(t *testing.T) {
		ll := logs.NewNopLogger()
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "",
		}

		manager, err := newOauth2ProxyReverseManager(ll, oauthArgs)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "oauth2-proxy upstream URL is required")
		assert.Nil(t, manager)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			ProxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		manager, err := newOauth2ProxyReverseManager(nil, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, manager)
	})
}

//

func Test_oauth2ProxyReverseManager_ExpandSources(t *testing.T) {
	t.Run("adds oauth2-proxy routes for each unique host", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
				CommunityID: "comm1",
			},
			{
				ID:          "route2",
				Source:      newURLString("https://api.example.com/v1"),
				Destination: newURLString("http://backend:8080"),
				CommunityID: "comm1",
			},
		}

		expanded := manager.ExpandSources(rawSources)

		assert.Len(t, expanded, 4)
		assert.Equal(t, "route1", expanded[0].ID)
		assert.Equal(t, "route1-oauth2-proxy", expanded[1].ID)
		assert.Equal(t, "route2", expanded[2].ID)
		assert.Equal(t, "route2-oauth2-proxy", expanded[3].ID)
	})

	t.Run("deduplicates oauth2-proxy routes for same host", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
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

		assert.Len(t, expanded, 3, "should have original 2 routes + 1 oauth2 route (deduplicated)")
	})

	t.Run("handles sources with nil URL", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
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

	t.Run("defaults to https scheme when missing", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("http://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		require.Len(t, expanded, 2)
		assert.Contains(t, expanded[1].Source.Raw, "http://")
	})

	t.Run("creates correct oauth2-proxy destination URL", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
			},
		}

		expanded := manager.ExpandSources(rawSources)

		require.Len(t, expanded, 2)
		oauth2Route := expanded[1]
		assert.Equal(t, "https://app.example.com/-/wormhole/oauth2", oauth2Route.Source.Raw)
		assert.Equal(t, "http://oauth2-proxy.svc.cluster.local:4180/oauth2", oauth2Route.Destination.Raw)
	})

	t.Run("preserves community ID in oauth2-proxy routes", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:               logs.NewNopLogger(),
			proxyUpstreamURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		rawSources := []wormhole.RawSource{
			{
				ID:          "route1",
				Source:      newURLString("https://app.example.com/api"),
				Destination: newURLString("http://backend:8080"),
				CommunityID: "test-community",
			},
		}

		expanded := manager.ExpandSources(rawSources)

		require.Len(t, expanded, 2)
		assert.Equal(t, "test-community", expanded[1].CommunityID)
	})
}

//

func Test_oauth2ProxyReverseManager_EstablishPreAuthentication(t *testing.T) {
	t.Run("skips auth for oauth2-proxy endpoints", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		preAuthFunc := manager.EstablishPreAuthentication(wormhole.RawSource{})
		details := requests.RequestDetails{
			Path: "/-/wormhole/oauth2/start",
		}

		skip, err := preAuthFunc(details)

		assert.True(t, skip)
		assert.Nil(t, err)
	})

	t.Run("does not skip auth for non-oauth2 endpoints", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		preAuthFunc := manager.EstablishPreAuthentication(wormhole.RawSource{})
		details := requests.RequestDetails{
			Path: "/api/v1/users",
		}

		skip, err := preAuthFunc(details)

		assert.False(t, skip)
		assert.Nil(t, err)
	})

	t.Run("skips auth for oauth2-proxy callback", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		preAuthFunc := manager.EstablishPreAuthentication(wormhole.RawSource{})
		details := requests.RequestDetails{
			Path: "/-/wormhole/oauth2/callback",
		}

		skip, err := preAuthFunc(details)

		assert.True(t, skip)
		assert.Nil(t, err)
	})

	t.Run("does not skip auth for similar but different paths", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		preAuthFunc := manager.EstablishPreAuthentication(wormhole.RawSource{})
		details := requests.RequestDetails{
			Path: "/-/wormhole/oauth2-something-else",
		}

		skip, err := preAuthFunc(details)

		assert.False(t, skip)
		assert.Nil(t, err)
	})
}

//

func Test_oauth2ProxyReverseManager_PrepareAuthRedirect(t *testing.T) {
	t.Run("creates redirect URL with proposed redirect", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "https",
		}
		proposedRedirect := "https://app.example.com/dashboard"

		redirectURL, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
		assert.Contains(t, redirectURL, "https://app.example.com/-/wormhole/oauth2/start")
		assert.Contains(t, redirectURL, "rd=https%3A%2F%2Fapp.example.com%2Fdashboard")
	})

	t.Run("defaults to https when scheme is empty", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "",
		}
		proposedRedirect := "https://app.example.com/dashboard"

		redirectURL, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
		assert.Contains(t, redirectURL, "https://app.example.com/-/wormhole/oauth2/start")
	})

	t.Run("URL encodes the redirect parameter", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		details := requests.RequestDetails{
			Host:   "app.example.com",
			Scheme: "https",
		}
		proposedRedirect := "https://app.example.com/path?key=value&foo=bar"

		redirectURL, err := manager.PrepareAuthRedirect(proposedRedirect, details)

		require.Nil(t, err)
		assert.Contains(t, redirectURL, "rd=https%3A%2F%2Fapp.example.com%2Fpath%3Fkey%3Dvalue%26foo%3Dbar")
	})
}

//

func Test_oauth2ProxyReverseManager_RedirectHandler(t *testing.T) {
	t.Run("returns error as redirect handler is not used", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll: logs.NewNopLogger(),
		}

		ctx := context.Background()
		details := requests.RequestDetails{}

		cookie, err := manager.RedirectHandler(ctx, details)

		assert.Nil(t, cookie)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "redirect handler not used in reverse proxy strategy")
	})
}

//

func Test_oauth2ProxyReverseManager_ValidateCookies(t *testing.T) {
	t.Run("validates cookie with custom cookie name", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_custom_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "_custom_session", Value: "session-token-123"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "session-token-123", result.AccessToken)
	})

	t.Run("validates cookie with default oauth2-proxy name", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "_oauth2_proxy", Value: "default-token-456"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "default-token-456", result.AccessToken)
	})

	t.Run("prefers custom cookie name over default", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_custom_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "_custom_session", Value: "custom-token"},
			{Name: "_oauth2_proxy", Value: "default-token"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "custom-token", result.AccessToken)
	})

	t.Run("returns error when no session cookie found", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_custom_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "other_cookie", Value: "other-value"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "oauth2-proxy session cookie not found")
		assert.Equal(t, "", result.AccessToken)
	})

	t.Run("returns error when cookies slice is empty", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_custom_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.NotNil(t, err)
		assert.Equal(t, "", result.AccessToken)
	})

	t.Run("finds cookie among multiple cookies", func(t *testing.T) {
		manager := &oauth2ProxyReverseManager{
			ll:         logs.NewNopLogger(),
			cookieName: "_wormhole_session",
		}

		ctx := context.Background()
		details := requests.RequestDetails{}
		cookies := []*http.Cookie{
			{Name: "cookie1", Value: "value1"},
			{Name: "cookie2", Value: "value2"},
			{Name: "_wormhole_session", Value: "target-token"},
			{Name: "cookie3", Value: "value3"},
		}

		result, err := manager.ValidateCookies(ctx, details, cookies)

		require.Nil(t, err)
		assert.Equal(t, "target-token", result.AccessToken)
	})
}
*/
