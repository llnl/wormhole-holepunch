package envoy

import (
	"errors"
	"testing"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

// findHeader returns the HeaderValueOption for the given key, or nil if absent.
func findHeader(headers []*envoy_core.HeaderValueOption, key string) *envoy_core.HeaderValueOption {
	for _, h := range headers {
		if h.GetHeader().GetKey() == key {
			return h
		}
	}

	return nil
}

func makeCheckRequest(headers, ctxExt map[string]string) *auth.CheckRequest {
	return &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: headers,
				},
			},
			ContextExtensions: ctxExt,
			Source: &auth.AttributeContext_Peer{
				Address: &envoy_core.Address{},
			},
		},
	}
}

//

func Test_authServer_establishReqDetails(t *testing.T) {
	t.Run("populates fields from context extensions", func(t *testing.T) {
		s := &authServer{
			tokenSvcArgs: args.TokenService{},
		}

		req := makeCheckRequest(
			map[string]string{
				"x-token": "tok-abc",
			},
			map[string]string{
				keys.PikoHeader:           "route-123",
				keys.WormholeHostHeader:   "api.example.com",
				keys.WormholeSchemeHeader: "https",
				keys.CommunityHeader:      "comm-456",
			},
		)

		got := s.establishReqDetails(req)

		assert.Equal(t, "route-123", got.RouteID)
		assert.Equal(t, "api.example.com", got.Host)
		assert.Equal(t, "https", got.Scheme)
		assert.Equal(t, "comm-456", got.CommunityID)
		assert.Equal(t, "tok-abc", got.Headers["x-token"])
	})

	t.Run("DevHostHeader overrides host from request header", func(t *testing.T) {
		s := &authServer{
			tokenSvcArgs: args.TokenService{
				DevHostHeader: "x-dev-host",
			},
		}

		req := makeCheckRequest(
			map[string]string{
				"x-dev-host": "dev.local",
			},
			map[string]string{
				keys.WormholeHostHeader:   "api.example.com",
				keys.WormholeSchemeHeader: "https",
			},
		)

		got := s.establishReqDetails(req)

		assert.Equal(t, "dev.local", got.Host)
	})

	t.Run("DevHostHeader absent leaves host from context extension", func(t *testing.T) {
		s := &authServer{
			tokenSvcArgs: args.TokenService{},
		}

		req := makeCheckRequest(
			map[string]string{
				"x-dev-host": "dev.local",
			},
			map[string]string{
				keys.WormholeHostHeader:   "api.example.com",
				keys.WormholeSchemeHeader: "https",
			},
		)

		got := s.establishReqDetails(req)

		assert.Equal(t, "api.example.com", got.Host)
	})

	t.Run("DevHostHeader set but header missing from request falls back to context extension", func(t *testing.T) {
		s := &authServer{
			tokenSvcArgs: args.TokenService{
				DevHostHeader: "x-dev-host",
			},
		}

		req := makeCheckRequest(
			map[string]string{},
			map[string]string{
				keys.WormholeHostHeader: "api.example.com",
			},
		)

		got := s.establishReqDetails(req)

		assert.Equal(t, "api.example.com", got.Host)
	})
}

func Test_authServer_denyRequest(t *testing.T) {
	t.Run("includes statusError headers", func(t *testing.T) {
		s := &authServer{}

		sErr := errs.NewAuthErr(errors.New("boom"), "denied", errs.WithHeaders(map[string]string{
			"x-retry-after": "30",
		}))

		resp := s.denyRequest(t.Context(), sErr, logs.InitializeDiscard())

		got := findHeader(resp.GetDeniedResponse().GetHeaders(), "x-retry-after")

		require.NotNil(t, got)
		assert.Equal(t, "30", got.GetHeader().GetValue())
	})
}

func Test_authServer_redirectRequest(t *testing.T) {

	t.Run("includes statusError headers", func(t *testing.T) {
		s := &authServer{}

		sErr := errs.NewRedirectErr("https://login.example.com", errs.WithHeaders(map[string]string{
			keys.SetCookieHeader: "session=abc123",
		}))

		resp := s.redirectRequest(t.Context(), requests.RequestDetails{}, sErr, logs.InitializeDiscard())

		got := findHeader(resp.GetDeniedResponse().GetHeaders(), keys.SetCookieHeader)

		require.NotNil(t, got)
		assert.Equal(t, "session=abc123", got.GetHeader().GetValue())
	})
}
