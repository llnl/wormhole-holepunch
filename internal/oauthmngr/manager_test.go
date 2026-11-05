package oauthmngr

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

var ll = logs.InitializeDiscard()

// echoProxy returns a requests.Client emulating oauth2-proxy's auth endpoint: any session
// prefixed "rejected" is refused (401), all others resolve to the access token "at:<session>".
func echoProxy(ctrl *gomock.Controller) requests.Client {
	m := mock_requests.NewMockClient(ctrl)
	m.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, url string, _ map[string]string, cookies []*http.Cookie) (map[string]string, *requests.RequestFailedError) {
			if len(cookies) != 1 || strings.HasPrefix(cookies[0].Value, "rejected") {
				return nil, &requests.RequestFailedError{Err: errors.New("unauthorized"), StatusCode: http.StatusUnauthorized, URL: url}
			}

			return map[string]string{keys.Oauth2ProxyAccessTokenHeader: "at:" + cookies[0].Value}, nil
		},
	).AnyTimes()

	return m
}

// mockKVStore to return anything. For tests that require specific behavior, you should set up
// expectations on the mock.
func mockKVStore(ctrl *gomock.Controller) streams.KVStore {
	m := mock_streams.NewMockKVStore(ctrl)
	m.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	m.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("cache miss")).AnyTimes()
	m.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return m
}

//

func Test_Validator_InterfaceCompliance(t *testing.T) {
	t.Run("noneManager implements Validator interface", func(t *testing.T) {
		var _ Validator = (*noneManager)(nil)
	})

	t.Run("reverseManager implements Validator interface", func(t *testing.T) {
		var _ Validator = (*reverseManager)(nil)
	})

	t.Run("middlewareManager implements Validator interface", func(t *testing.T) {
		var _ Validator = (*middlewareManager)(nil)
	})
}

func Test_Disabled(t *testing.T) {
	assert.IsType(t, &noneManager{}, Disabled())
}

func Test_Initialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("initializes none manager with explicit none strategy", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy: "none",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, validator)
		assert.IsType(t, &noneManager{}, validator)
	})

	t.Run("initializes none manager when strategy is empty", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy: "",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, validator)
		assert.IsType(t, &noneManager{}, validator)
	})

	t.Run("initializes oauth2-proxy-reverse manager with valid configuration", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy:         "oauth2-proxy-reverse",
			InternalProxyURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, validator)
		assert.IsType(t, &reverseManager{}, validator)
	})

	t.Run("returns error for oauth2-proxy-reverse when proxy upstream URL is missing", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy:         "oauth2-proxy-reverse",
			InternalProxyURL: "",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "internal URL is required")
		assert.Nil(t, validator)
	})

	t.Run("initializes oauth2-proxy-middleware manager with valid configuration", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy:         "oauth2-proxy-middleware",
			InternalProxyURL: "http://oauth2-proxy.svc.cluster.local:4180",
			UserAuthURL:      "auth.example.com",
			NonceTTL:         300,
			CookieMaxAge:     43200,
			CookieName:       "_wormhole_session",
		}

		validator, err := Initialize(mockKVStore(ctrl), nil, ll, oauthArgs)

		require.NoError(t, err)
		require.NotNil(t, validator)
		assert.IsType(t, &middlewareManager{}, validator)
	})

	t.Run("returns error for oauth2-proxy-middleware when proxy upstream URL is missing", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy:    "oauth2-proxy-middleware",
			UserAuthURL: "auth.example.com",
		}

		validator, err := Initialize(mockKVStore(ctrl), nil, ll, oauthArgs)

		require.Error(t, err)
		assert.Nil(t, validator)
	})

	t.Run("returns error for oauth2-proxy-middleware when auth domain is missing", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy:         "oauth2-proxy-middleware",
			InternalProxyURL: "http://oauth2-proxy.svc.cluster.local:4180",
		}

		validator, err := Initialize(mockKVStore(ctrl), nil, ll, oauthArgs)

		require.Error(t, err)
		assert.Nil(t, validator)
	})

	t.Run("returns error for unknown strategy", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy: "unknown",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.Error(t, err)
		assert.ErrorContains(t, err, "unknown")
		assert.Nil(t, validator)
	})

	t.Run("returns error for typo in strategy name", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy: "oauth2-proxy-middlewear",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.Error(t, err)
		assert.ErrorContains(t, err, "oauth2-proxy-middlewear")
		assert.Nil(t, validator)
	})

	t.Run("returns error for random string", func(t *testing.T) {
		oauthArgs := args.OauthManagement{
			Strategy: "random-string-123",
		}

		validator, err := Initialize(nil, nil, ll, oauthArgs)

		require.Error(t, err)
		assert.ErrorContains(t, err, "random-string-123")
		assert.Nil(t, validator)
	})

	t.Run("all valid strategies do not return error", func(t *testing.T) {
		validStrategies := []string{"none", "", "oauth2-proxy-reverse", "oauth2-proxy-middleware"}

		for _, strategy := range validStrategies {
			oauthArgs := args.OauthManagement{
				Strategy:         strategy,
				InternalProxyURL: "http://oauth2-proxy.svc.cluster.local:4180",
				UserAuthURL:      "https://auth.example.com",
				NonceTTL:         300,
				CookieMaxAge:     43200,
				CookieName:       "_wormhole_session",
			}

			validator, err := Initialize(mockKVStore(ctrl), nil, ll, oauthArgs)

			require.NoError(t, err)

			if strategy == "none" || strategy == "" {
				assert.NoError(t, err, "strategy %q should not return error", strategy)
				assert.NotNil(t, validator, "strategy %q should return a validator", strategy)
			}
		}
	})
}
