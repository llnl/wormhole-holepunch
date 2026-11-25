package proxyauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
)

func Test_ParseSessionStore(t *testing.T) {
	store, err := ParseSessionStore("")
	require.NoError(t, err)
	assert.Equal(t, oauthapi.SessionStoreCookie, store)

	store, err = ParseSessionStore("redis")
	require.NoError(t, err)
	assert.Equal(t, oauthapi.SessionStoreRedis, store)

	_, err = ParseSessionStore("memcached")
	require.ErrorContains(t, err, "memcached")
}

func Test_Resolver_Resolve(t *testing.T) {
	t.Run("joins browser chunks and presents the proxy cookie with default HTTPS scheme", func(t *testing.T) {
		client := mock_requests.NewMockClient(gomock.NewController(t))
		client.EXPECT().GetHeaders(
			gomock.Any(), testProxyURL+paths.Oauth2ProxyAuthPath,
			map[string]string{
				keys.XForwardHostHeader: "foo.example.com", keys.XForwardProtoHeader: "https", keys.XForwardURIHeader: "/app",
			},
			[]*http.Cookie{{Name: "_oauth2_proxy", Value: "session"}},
		).Return(map[string]string{keys.Oauth2ProxyAccessTokenHeader: "token"}, nil)

		result, sErr := New(client, ll, testProxyURL, "_oauth2_proxy").Resolve(
			context.Background(),
			requests.RequestDetails{
				Host: "foo.example.com", Path: "/app",
				Headers: map[string]string{keys.CookieHeader: "a=1; _browser_0=ses; _browser_1=sion; b=2"},
			},
			"_browser", oauthapi.SessionStoreCookie,
		)
		require.Nil(t, sErr)
		assert.Equal(t, Result{AccessToken: "token", CookieHeader: "a=1; b=2"}, result)
	})

	t.Run("unusable cookie never calls oauth2-proxy", func(t *testing.T) {
		client := mock_requests.NewMockClient(gomock.NewController(t))
		result, sErr := New(client, ll, testProxyURL, "_oauth2_proxy").Resolve(
			context.Background(),
			requests.RequestDetails{Headers: map[string]string{keys.CookieHeader: "_browser_0=session"}},
			"_browser", oauthapi.SessionStoreRedis,
		)
		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
		assert.Empty(t, result)
	})

	for name, tc := range map[string]struct {
		status int
		code   codes.Code
	}{
		"rejected session": {status: http.StatusUnauthorized, code: codes.Unauthenticated},
		"proxy failure":    {status: http.StatusBadGateway, code: codes.Internal},
	} {
		t.Run(name+" returns no partial result", func(t *testing.T) {
			client := mock_requests.NewMockClient(gomock.NewController(t))
			client.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
				nil, &requests.RequestFailedError{Err: errors.New(name), StatusCode: tc.status},
			)
			result, sErr := New(client, ll, testProxyURL, "_oauth2_proxy").Resolve(
				context.Background(),
				requests.RequestDetails{Headers: map[string]string{keys.CookieHeader: "_browser=session; a=1"}},
				"_browser", oauthapi.SessionStoreCookie,
			)
			require.NotNil(t, sErr)
			assert.Equal(t, int32(tc.code), sErr.Code())
			assert.Empty(t, result)
		})
	}
}

func Test_Resolver_sessionFromCookies(t *testing.T) {
	big := strings.Repeat("a", oauthapi.CookieChunkSize) + "bc"
	chunked := "x=1; _s_0=" + big[:oauthapi.CookieChunkSize] + "; y=2; _s_1=bc"

	withCookies := func(header string) requests.RequestDetails {
		return requests.RequestDetails{Headers: map[string]string{keys.CookieHeader: header}}
	}

	t.Run("single cookie in either store", func(t *testing.T) {
		for _, store := range []oauthapi.SessionStore{oauthapi.SessionStoreCookie, oauthapi.SessionStoreRedis} {
			result, sErr := New(nil, ll, "", "").sessionFromCookies(withCookies("x=1; _s=v; y=2"), "_s", store)

			require.Nil(t, sErr, store)
			assert.Equal(t, "v", result.AccessToken)
			assert.Equal(t, "x=1; y=2", result.CookieHeader)
		}
	})

	t.Run("chunks joined with the cookie store", func(t *testing.T) {
		result, sErr := New(nil, ll, "", "").sessionFromCookies(withCookies(chunked), "_s", oauthapi.SessionStoreCookie)

		require.Nil(t, sErr)
		assert.Equal(t, big, result.AccessToken)
		assert.Equal(t, "x=1; y=2", result.CookieHeader, "every chunk is stripped")
	})

	t.Run("chunks rejected with the redis store", func(t *testing.T) {
		_, sErr := New(nil, ll, "", "").sessionFromCookies(withCookies(chunked), "_s", oauthapi.SessionStoreRedis)

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("missing cookie", func(t *testing.T) {
		_, sErr := New(nil, ll, "", "").sessionFromCookies(withCookies("x=1"), "_s", oauthapi.SessionStoreCookie)

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})
}
