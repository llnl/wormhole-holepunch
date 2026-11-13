package envoy

import (
	"errors"
	"testing"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_registry"
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

func Test_authServer_allowRequest_CookieCleanup(t *testing.T) {
	ll := logs.InitializeDiscard()
	s := &authServer{ll: ll}

	t.Run("overwrites the original cookie header", func(t *testing.T) {
		resp := s.allowRequest(t.Context(), token.AuthResponse{
			SetHeaders: map[string]string{keys.CookieHeader: "app=keep"},
		}, ll)
		header := findHeader(resp.GetOkResponse().GetHeaders(), keys.CookieHeader)
		require.NotNil(t, header)
		assert.Equal(t, "app=keep", header.GetHeader().GetValue())
		assert.Equal(t, envoy_core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, header.GetAppendAction())
	})

	t.Run("removes a session-only cookie header", func(t *testing.T) {
		resp := s.allowRequest(t.Context(), token.AuthResponse{
			RemoveHeaders: []string{keys.CookieHeader},
		}, ll)
		assert.Equal(t, []string{keys.CookieHeader}, resp.GetOkResponse().GetHeadersToRemove())
		assert.Nil(t, findHeader(resp.GetOkResponse().GetHeaders(), keys.CookieHeader))
	})
}

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
				keys.RouteIDHeader:        "route-123",
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

	t.Run("path from the request, including the query", func(t *testing.T) {
		req := makeCheckRequest(map[string]string{}, map[string]string{})
		req.Attributes.Request.Http.Path = "/app?x=1"

		got := (&authServer{}).establishReqDetails(req)

		assert.Equal(t, "/app?x=1", got.Path)
	})

	t.Run("client IP from the downstream source address", func(t *testing.T) {
		req := makeCheckRequest(map[string]string{}, map[string]string{})
		req.Attributes.Source = &auth.AttributeContext_Peer{
			Address: &envoy_core.Address{Address: &envoy_core.Address_SocketAddress{
				SocketAddress: &envoy_core.SocketAddress{
					Address:       "10.0.0.1",
					PortSpecifier: &envoy_core.SocketAddress_PortValue{PortValue: 51234},
				},
			}},
		}

		got := (&authServer{}).establishReqDetails(req)

		assert.Equal(t, "10.0.0.1", got.ClientIP)
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	routeReg := mock_registry.NewMockRouter(ctrl)
	routeReg.EXPECT().AllowedRedirect(gomock.Any()).Return(true).AnyTimes()

	t.Run("includes statusError headers", func(t *testing.T) {
		s := &authServer{
			routeReg: routeReg,
		}

		sErr := errs.NewRedirectErr("https://login.example.com", errs.WithHeaders(map[string]string{
			keys.SetCookieHeader: "session=abc123",
		}))

		resp := s.redirectRequest(t.Context(), requests.RequestDetails{}, sErr, logs.InitializeDiscard())

		got := findHeader(resp.GetDeniedResponse().GetHeaders(), keys.SetCookieHeader)

		require.NotNil(t, got)
		assert.Equal(t, "session=abc123", got.GetHeader().GetValue())
	})

	t.Run("invalid redirect URL", func(t *testing.T) {
		invalidReg := mock_registry.NewMockRouter(ctrl)
		invalidReg.EXPECT().AllowedRedirect("https://foo.example.com").Return(false)

		s := &authServer{
			routeReg: invalidReg,
		}

		sErr := errs.NewRedirectErr("https://foo.example.com", errs.WithHeaders(map[string]string{
			keys.SetCookieHeader: "session=abc123",
		}))

		resp := s.redirectRequest(t.Context(), requests.RequestDetails{}, sErr, logs.InitializeDiscard())

		assert.Equal(t, typev3.StatusCode_BadRequest, resp.GetDeniedResponse().GetStatus().GetCode())
	})
}
