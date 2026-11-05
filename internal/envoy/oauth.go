package envoy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	wasmfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

// This file builds the Envoy resources required by oauthmngr (see docs/oauth-manager.md).
// Which routes skip authentication is decided by oauthmngr's ExpandSources, tagging each
// injected route with a registry.RouteKind; the kind alone determines the route action and
// per-route filter configuration generated here:
//
//	| Kind           | Route action                    | ext_authz | oauthmngr wasm |
//	|----------------|---------------------------------|-----------|----------------|
//	| upstream       | forward to destination cluster  | enabled   | disabled       |
//	| oauth2-proxy   | forward to oauth2-proxy cluster | disabled  | disabled       |
//	| oauth-callback | direct_response 404             | disabled  | enabled        |
//	| reserved       | direct_response 404             | disabled  | disabled       |

const (
	oauthWasmFilter = "envoy.filters.http.wasm.oauthmngr"
	oauthWasmName   = "oauthmngr"
	wasmRuntimeV8   = "envoy.wasm.runtime.v8"

	notFoundStatus = 404
)

// oauthPlugin holds the oauthmngr wasm plugin configuration, nil when the configured strategy
// requires no plugin.
type oauthPlugin struct {
	cfg       *oauthmngr.PluginConfig
	wasmPath  string
	ledgerURL *url.URL
}

// newOauthPlugin validates that the Envoy-side settings required by the strategy's plugin
// are present, returning nil when no plugin is required.
func newOauthPlugin(validator oauthmngr.Validator, oauthArgs args.OauthManagement) (*oauthPlugin, error) {
	cfg, ok := validator.WasmPluginConfig()
	if !ok {
		return nil, nil //nolint:nilnil // no plugin is a valid, non-error outcome
	}

	if oauthArgs.OauthWasmPath == "" {
		return nil, errors.New("oauth wasm path is required by the configured oauth strategy")
	}

	if oauthArgs.OauthLedgerURL == "" {
		return nil, errors.New("oauth ledger URL is required by the configured oauth strategy")
	}

	ledgerURL, err := parseLedgerURL(oauthArgs.OauthLedgerURL)
	if err != nil {
		return nil, err
	}

	return &oauthPlugin{
		cfg: cfg, wasmPath: oauthArgs.OauthWasmPath, ledgerURL: ledgerURL,
	}, nil
}

func parseLedgerURL(raw string) (*url.URL, error) {
	ledgerURL, err := url.Parse(raw)
	if err != nil || ledgerURL.Hostname() == "" {
		return nil, errors.New("invalid oauth ledger URL: an absolute HTTP or HTTPS origin is required")
	}

	if ledgerURL.Scheme != "http" && ledgerURL.Scheme != "https" {
		return nil, errors.New("oauth ledger URL scheme must be http or https")
	}

	if ledgerURL.User != nil || (ledgerURL.Path != "" && ledgerURL.Path != "/") ||
		ledgerURL.RawQuery != "" || ledgerURL.ForceQuery || ledgerURL.Fragment != "" {
		return nil, errors.New("oauth ledger URL must be an origin without credentials, a path prefix, query, or fragment")
	}

	if ledgerURL.Port() != "" {
		port, err := strconv.ParseUint(ledgerURL.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("oauth ledger URL port must be between 1 and 65535")
		}
	} else if ledgerURL.Host[len(ledgerURL.Host)-1] == ':' {
		return nil, errors.New("oauth ledger URL must not contain an empty port")
	}

	return ledgerURL, nil
}

// wasmHTTPFilter establishes the oauthmngr wasm filter, failing closed so a VM crash or load
// failure is never an unauthenticated pass-through. It is enabled in the HCM and disabled on
// every route other than oauth-callback routes (see wasmPerRoute): Envoy rejects an empty
// per-route FilterConfig that enables a filter, and the wasm filter offers no per-route
// configuration to provide, whereas an empty FilterConfig disabling it is accepted.
func (p *oauthPlugin) wasmHTTPFilter() *hcm.HttpFilter {
	configuration, err := json.Marshal(p.cfg)
	if err != nil {
		// Only possible during development, PluginConfig is a plain struct.
		panic(err)
	}

	plugin := &wasmfilter.Wasm{
		Config: &wasm.PluginConfig{
			Name:   oauthWasmName,
			RootId: oauthWasmName,
			Vm: &wasm.PluginConfig_VmConfig{
				VmConfig: &wasm.VmConfig{
					VmId:    oauthWasmName,
					Runtime: wasmRuntimeV8,
					Code: &core.AsyncDataSource{
						Specifier: &core.AsyncDataSource_Local{
							Local: &core.DataSource{
								Specifier: &core.DataSource_Filename{Filename: p.wasmPath},
							},
						},
					},
				},
			},
			// StringValue is passed to the plugin directly, without the wrapper.
			Configuration: mustMarshalAny(wrapperspb.String(string(configuration))),
			FailurePolicy: wasm.FailurePolicy_FAIL_CLOSED,
		},
	}

	return &hcm.HttpFilter{
		Name:       oauthWasmFilter,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: mustMarshalAny(plugin)},
	}
}

// ledgerCluster establishes the cluster the wasm plugin dispatches Ledger calls to.
func (p *oauthPlugin) ledgerCluster(connectTimeout *durationpb.Duration) *cluster.Cluster {
	c := &cluster.Cluster{
		Name:                 p.cfg.LedgerCluster,
		ConnectTimeout:       connectTimeout,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint(p.cfg.LedgerCluster, p.ledgerURL),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
	if p.ledgerURL.Scheme == "https" {
		host := p.ledgerURL.Hostname()
		sanType := tls.SubjectAltNameMatcher_DNS
		sni := host

		if net.ParseIP(host) != nil {
			sanType = tls.SubjectAltNameMatcher_IP_ADDRESS
			sni = ""
		}

		validation := &tls.CertificateValidationContext{
			SystemRootCerts: &tls.CertificateValidationContext_SystemRootCerts{},
			MatchTypedSubjectAltNames: []*tls.SubjectAltNameMatcher{{
				SanType: sanType,
				Matcher: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: host}},
			}},
		}

		c.TransportSocket = &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: mustMarshalAny(&tls.UpstreamTlsContext{
				Sni: sni,
				CommonTlsContext: &tls.CommonTlsContext{
					ValidationContextType: &tls.CommonTlsContext_ValidationContext{ValidationContext: validation},
				},
			})},
		}
	}

	return c
}

//

// wasmPerRoute disables the oauthmngr wasm filter on every route other than oauth-callback
// routes, the only routes the plugin may answer. Every generated route must pass through
// this, Test_oauthSnapshot_middleware verifies it.
func (s *xdsServer) wasmPerRoute(perFilter map[string]*anypb.Any, kind registry.RouteKind) {
	if s.oauthPlugin == nil || kind == registry.RouteKindOauthCallback {
		return
	}

	perFilter[oauthWasmFilter] = mustMarshalAny(&route.FilterConfig{Disabled: true})
}

// forwardsUpstream reports whether the route kind proxies to a destination cluster.
func forwardsUpstream(kind registry.RouteKind) bool {
	return kind == registry.RouteKindUpstream || kind == registry.RouteKindOauth2Proxy
}

// localReplyRoute builds a route answered by Envoy itself, with ext_authz disabled. The 404
// is a fallback for oauth-callback routes, where the wasm plugin always replies first.
func (s *xdsServer) localReplyRoute(prefix string, ctl registry.ProxyControls) *route.Route {
	perFilter := map[string]*anypb.Any{
		authzFilter: routeAuthzFilter(ctl),
	}

	s.wasmPerRoute(perFilter, ctl.Kind)

	return &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{Prefix: prefix},
		},
		Action: &route.Route_DirectResponse{
			DirectResponse: &route.DirectResponseAction{Status: notFoundStatus},
		},
		Metadata:             routeMetadata(ctl),
		TypedPerFilterConfig: perFilter,
	}
}
