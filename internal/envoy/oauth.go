package envoy

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

// This file builds the Envoy resources required by oauthmngr (see docs/oauth-manager.md).
// Which routes skip authentication is decided by oauthmngr's ExpandSources, tagging each
// injected route with a registry.RouteKind; the kind alone determines the route action and
// per-route configuration generated here:
//
//	| Kind           | Route action                        | ext_authz |
//	|----------------|-------------------------------------|-----------|
//	| upstream       | forward to destination cluster      | enabled   |
//	| oauth2-proxy   | forward to oauth2-proxy cluster     | disabled  |
//	| oauth-callback | forward to oauthmngr ledger cluster | disabled  |
//	| reserved       | direct_response 404                 | disabled  |

const (
	notFoundStatus = 404

	// downstreamAddress is the client address as seen by ext_authz (attributes.source.address).
	downstreamAddress = "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
)

// forwardsUpstream reports whether the route kind proxies to a destination cluster.
func forwardsUpstream(kind registry.RouteKind) bool {
	return kind == registry.RouteKindUpstream ||
		kind == registry.RouteKindOauth2Proxy ||
		kind == registry.RouteKindOauthCallback
}

// callbackRequestHeaders binds the client address and the matched route's host and scheme
// into the request forwarded to the oauthmngr ledger, overwriting any client supplied value.
// These are the same values ext_authz binds the OAuth nonce to when minting it.
func callbackRequestHeaders(ctl registry.ProxyControls) []*core.HeaderValueOption {
	header := func(key, value string) *core.HeaderValueOption {
		return &core.HeaderValueOption{
			Header:       &core.HeaderValue{Key: key, Value: value},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}
	}

	return []*core.HeaderValueOption{
		header(keys.ClientIPHeader, downstreamAddress),
		header(keys.WormholeHostHeader, ctl.Source.URL.Host),
		header(keys.WormholeSchemeHeader, ctl.Source.URL.Scheme),
	}
}

// localReplyRoute builds a route answered by Envoy itself with a 404, with ext_authz disabled.
func (s *xdsServer) localReplyRoute(prefix string, ctl registry.ProxyControls) *route.Route {
	return &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{Prefix: prefix},
		},
		Action: &route.Route_DirectResponse{
			DirectResponse: &route.DirectResponseAction{Status: notFoundStatus},
		},
		Metadata: routeMetadata(ctl),
		TypedPerFilterConfig: map[string]*anypb.Any{
			authzFilter: routeAuthzFilter(ctl),
		},
	}
}
