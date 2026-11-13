package proxyauth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
)

const testProxyURL = "http://oauth2-proxy.svc.cluster.local:4180"

var ll = logs.InitializeDiscard()

func Test_proxyAuth_accessToken(t *testing.T) {
	details := requests.RequestDetails{Host: "foo.example.com", Scheme: "https", Path: "/app?x=1"}

	t.Run("invalid request cookie fails before sending a request", func(t *testing.T) {
		client := mock_requests.NewMockClient(gomock.NewController(t))
		token, sErr := New(client, ll, testProxyURL, "bad;name").accessToken(context.Background(), details, "session")

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
		assert.Empty(t, token)
	})

	t.Run("presents the unsplit session to the auth endpoint", func(t *testing.T) {
		client := mock_requests.NewMockClient(gomock.NewController(t))
		client.EXPECT().GetHeaders(
			gomock.Any(),
			testProxyURL+"/-/wormhole/oauth2/auth",
			map[string]string{
				keys.XForwardHostHeader:  "foo.example.com",
				keys.XForwardProtoHeader: "https",
				keys.XForwardURIHeader:   "/app?x=1",
			},
			[]*http.Cookie{{Name: "_oauth2_proxy", Value: "session"}},
		).Return(map[string]string{keys.Oauth2ProxyAccessTokenHeader: "access"}, nil)

		token, sErr := New(client, ll, testProxyURL, "_oauth2_proxy").accessToken(context.Background(), details, "session")

		require.Nil(t, sErr)
		assert.Equal(t, "access", token)
	})

	failures := map[string]struct {
		headers map[string]string
		rErr    *requests.RequestFailedError
		code    codes.Code
	}{
		"session rejected (401)": {
			rErr: &requests.RequestFailedError{Err: errors.New("no"), StatusCode: http.StatusUnauthorized},
			code: codes.Unauthenticated,
		},
		"session forbidden (403)": {
			rErr: &requests.RequestFailedError{Err: errors.New("no"), StatusCode: http.StatusForbidden},
			code: codes.Unauthenticated,
		},
		"oauth2-proxy error": {
			rErr: &requests.RequestFailedError{Err: errors.New("boom"), StatusCode: http.StatusBadGateway},
			code: codes.Internal,
		},
		"oauth2-proxy unreachable": {
			rErr: &requests.RequestFailedError{Err: errors.New("dial")},
			code: codes.Internal,
		},
		"access token not passed": {
			headers: map[string]string{"x-auth-request-user": "u"},
			code:    codes.Internal,
		},
	}

	for name, tc := range failures {
		t.Run(name, func(t *testing.T) {
			client := mock_requests.NewMockClient(gomock.NewController(t))
			client.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.headers, tc.rErr)

			_, sErr := New(client, ll, testProxyURL, "_oauth2_proxy").accessToken(context.Background(), details, "session")

			require.NotNil(t, sErr)
			assert.Equal(t, int32(tc.code), sErr.Code())
		})
	}
}
