package envoy

import (
	"testing"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

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
