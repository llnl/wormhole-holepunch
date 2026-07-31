package envoy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutation_rules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	trace "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	header_mutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/version"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

const (
	accessLogFilter      = "envoy.access_loggers.file"
	authzFilter          = "envoy.filters.http.ext_authz"
	headerMutationFilter = "envoy.filters.http.header_mutation"
	httpRouteFilter      = "http-router"
)

// makeClusters generates a list of Envoy cluster resources based on the ProxyControls configuration.
// Each cluster is uniquely identified by its name and is configured to use Logical DNS discovery,
// round-robin load balancing, and IPv4 DNS lookup.
func (s *xdsServer) makeClusters(ctls map[string]registry.ProxyControls) []types.Resource {
	clusterMappings := make(map[string]bool, 0)
	clusters := make([]types.Resource, 0)

	for k, v := range ctls {
		name := clusterName(v.Destination.URL)

		if !clusterMappings[name] {
			clusterMappings[name] = true
			clusters = append(
				clusters,
				&cluster.Cluster{
					Name:                 name,
					ConnectTimeout:       durationpb.New(s.xdsArgs.ConnectTimeout),
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
					LbPolicy:             cluster.Cluster_ROUND_ROBIN,
					LoadAssignment:       makeEndpoint(k, v.Destination.URL),
					DnsLookupFamily:      cluster.Cluster_V4_ONLY,
				},
			)
		}
	}

	return clusters
}

// makeEndpoint creates an endpoint configuration for a given cluster using a target URL.
func makeEndpoint(clusterName string, dst *url.URL) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  dst.Hostname(),
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: requests.IdentifyPort(dst),
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

/*
	Route Type
*/

// makeRoutes builds an Envoy route configuration. Routes are mapped to their respective clusters
// based on the provided ProxyControls configuration.
func (s *xdsServer) makeRoutes(
	routeName string,
	ctls map[string]registry.ProxyControls,
) *route.RouteConfiguration {
	vhMappings := make(map[string]*route.VirtualHost, 0)

	for routeID, v := range ctls {
		domainName := domain(v.Source.URL)

		prefix := requests.NormalizePath(v.Source.URL)

		newRoute := s.singleRoute(
			clusterName(v.Destination.URL),
			prefix,
			v.PrefixRewrite,
			v,
			routeID,
		)

		vh, found := vhMappings[domainName]
		if found {
			// Insert newRoute into vh.Routes based on the prefix length, this should ensure
			// that to a "reasonable" degree we will act upon the desired prefix match. This
			// is not free from undesired behavior and we should convey this to teams relying
			// on paths in their route registration.
			insertPosition := len(vh.GetRoutes())

			for i, existingRoute := range vh.GetRoutes() {
				if len(newRoute.GetMatch().GetPrefix()) > len(existingRoute.GetMatch().GetPrefix()) {
					insertPosition = i
					break
				}
			}

			vh.Routes = append(
				vh.Routes[:insertPosition],
				append([]*route.Route{newRoute}, vh.GetRoutes()[insertPosition:]...)...,
			)
		} else {
			vhMappings[domainName] = &route.VirtualHost{
				Name:    virtualHostName(domainName),
				Domains: []string{domainName},
				Routes:  []*route.Route{newRoute},
			}
		}
	}

	virtualHosts := make([]*route.VirtualHost, 0, len(vhMappings))

	for _, v := range vhMappings {
		virtualHosts = append(virtualHosts, v)
	}

	return &route.RouteConfiguration{
		Name:         routeName,
		VirtualHosts: virtualHosts,
	}
}

// singleRoute creates a single route mapping HTTP requests to a specific Envoy cluster. The
// route rewrites the request path, modifies request headers, and applies filtering configurations.
func (s *xdsServer) singleRoute(
	clusterName, prefix, prefixRewrite string,
	ctl registry.ProxyControls,
	routeID string,
) *route.Route {
	ra := &route.Route_Route{
		Route: &route.RouteAction{
			ClusterSpecifier: &route.RouteAction_Cluster{
				Cluster: clusterName,
			},
			HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
				HostRewriteLiteral: ctl.Destination.URL.Host,
			},
			PrefixRewrite: prefixRewrite,
			IdleTimeout:   durationpb.New(s.xdsArgs.IdleTimeout),
			Timeout:       durationpb.New(s.xdsArgs.RequestTimeout),
			MaxStreamDuration: &route.RouteAction_MaxStreamDuration{
				MaxStreamDuration: durationpb.New(s.xdsArgs.MaxStreamDuration),
			},
		},
	}

	if s.xdsArgs.EnableWebSocket {
		ra.Route.UpgradeConfigs = []*route.RouteAction_UpgradeConfig{
			{UpgradeType: "websocket"},
		}
	}

	return &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: prefix,
			},
		},
		Action: ra,
		TypedPerFilterConfig: map[string]*anypb.Any{
			headerMutationFilter: s.requestHeaderFilterCfg(ctl.RequestHeaders),
			authzFilter:          buildAuthzFilter(ctl, routeID),
		},
	}
}

// domain extracts the domain name from the provided URL. If the URL points to localhost,
// a wildcard domain (*) is returned.
func domain(src *url.URL) string {
	domain := src.Hostname()
	if requests.IsLocalhost(src) {
		domain = "*"
	}

	return domain
}

// virtualHostName generates a unique identifier for a virtual host by hashing its
// domain name using SHA256.
func virtualHostName(domainName string) string {
	hash := sha256.Sum256([]byte(domainName))

	return hex.EncodeToString(hash[:])
}

func buildAuthzFilter(ctl registry.ProxyControls, routeID string) *anypb.Any {
	ctxExt := map[string]string{
		keys.PikoHeader:           routeID,
		keys.WormholeHostHeader:   ctl.Source.URL.Host,
		keys.WormholeSchemeHeader: ctl.Source.URL.Scheme,
	}

	if ctl.CommunityID != "" {
		ctxExt[keys.CommunityHeader] = ctl.CommunityID
	}

	return mustMarshalAny(&extauthz.ExtAuthzPerRoute{
		// Bind host and scheme from the matched route config into context_extensions so
		// ext_authz receives values that reflect actual routing, not client-supplied headers.
		Override: &extauthz.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &extauthz.CheckSettings{
				ContextExtensions: ctxExt,
			},
		},
	})
}

/*
	Listener Type
*/

// makeHTTPListener creates an Envoy HTTP listener with a connection manager filter chain. The
// listener is configured with all required header mutations, auth enforcement,
// access logging, and optional WebSocket support.
func (s *xdsServer) makeHTTPListener(listenerName, routeName string) *listener.Listener {
	routerConfig := mustMarshalAny(&router.Router{})
	headerMutationFilterConfig := mustMarshalAny(&header_mutation.HeaderMutation{})

	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",

		// Manage these setting to ensure the authorized/request paths do not diverge.
		NormalizePath: &wrapperspb.BoolValue{
			Value: true,
		},
		MergeSlashes:                 true,
		PathWithEscapedSlashesAction: hcm.HttpConnectionManager_UNESCAPE_AND_REDIRECT,

		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    s.configSource(),
				RouteConfigName: routeName,
			},
		},
		HttpFilters: []*hcm.HttpFilter{
			{
				Name: headerMutationFilter,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: headerMutationFilterConfig,
				},
			},
			{
				// Required ext_authz filter
				Name: authzFilter,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: s.authzFilterCfg(),
				},
			},
			{
				// Router filter - last in the chain
				Name: httpRouteFilter,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: routerConfig,
				},
			},
		},
		AccessLog: []*accesslog.AccessLog{{
			// Access log configuration
			Name: accessLogFilter,
			ConfigType: &accesslog.AccessLog_TypedConfig{
				TypedConfig: accessLogCfg(),
			},
		}},
		Tracing:        s.makeTracingCfg(),
		UpgradeConfigs: nil,
	}

	if s.xdsArgs.EnableWebSocket {
		manager.UpgradeConfigs = []*hcm.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		}
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  s.xdsArgs.ListenerAddress,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: s.xdsArgs.ListenerPort,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: "http-connection-manager",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: mustMarshalAny(manager),
				},
			}},
		}},
	}
}

// configSource defines the xDS configuration source, specifying how Envoy fetches
// its configuration. This function sets up GRPC as the transport protocol.
func (s *xdsServer) configSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: s.xdsArgs.ClusterName},
				},
			}},
		},
	}

	return source
}

// authzFilterCfg creates the configuration for the external authorization filter
// (ext_authz) to delegate authorization decisions to an external gRPC-based service.
func (s *xdsServer) authzFilterCfg() *anypb.Any {
	extAuthzConfig := &extauthz.ExtAuthz{
		Services: &extauthz.ExtAuthz_GrpcService{
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: s.xdsArgs.AuthCluster,
					},
				},
				Timeout: durationpb.New(s.xdsArgs.AuthTimeout),
			},
		},
		TransportApiVersion: core.ApiVersion_V3,
		// If this option isn't specified, then all client request headers are included in the check request to a
		// gRPC authorization server; however, even after setting these there are several included by default:
		// “Host“, “Method“, “Path“, “Content-Length“, and “Authorization“.
		AllowedHeaders: &matcher.ListStringMatcher{
			Patterns: []*matcher.StringMatcher{
				{
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: s.tokenSvcArgs.TokenHeader,
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: s.tokenSvcArgs.SubtokenHeader,
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: keys.RequestIDHeader,
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: "cookie",
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: "upgrade",
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: "connection",
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Prefix{
						Prefix: "sec-websocket-",
					},
				}, {
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: keys.CommunityHeader,
					},
				},
			},
		},
	}

	return mustMarshalAny(extAuthzConfig)
}

// requestHeaderFilterCfg defines the configuration for modifying request headers through the
// header mutation filter. Adds the provided headers to all upstream requests and optionally
// includes a version header.
func (s *xdsServer) requestHeaderFilterCfg(set map[string]string) *anypb.Any {
	headerMutationConfig := &header_mutation.HeaderMutationPerRoute{
		Mutations: &header_mutation.Mutations{
			RequestMutations: s.defaultRequestHeaders,
		},
	}

	for k, v := range set {
		headerMutationConfig.Mutations.RequestMutations = append(
			headerMutationConfig.Mutations.RequestMutations,
			s.setHeader(k, v),
		)
	}

	if s.xdsArgs.VersionHeader {
		headerMutationConfig.Mutations.RequestMutations = append(
			headerMutationConfig.Mutations.RequestMutations,
			s.setHeader(keys.VersionHeader, version.GetVersion()),
		)
	}

	return mustMarshalAny(headerMutationConfig)
}

func (s *xdsServer) makeTracingCfg() *hcm.HttpConnectionManager_Tracing {
	if !s.xdsArgs.CollectorEnabled {
		return nil
	}

	otelCfg := &trace.OpenTelemetryConfig{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
					ClusterName: s.xdsArgs.CollectorCluster,
				},
			},
		},
		ServiceName: s.xdsArgs.CollectorService,
	}

	return &hcm.HttpConnectionManager_Tracing{
		Provider: &trace.Tracing_Http{
			Name: "envoy.tracers.opentelemetry",
			ConfigType: &trace.Tracing_Http_TypedConfig{
				TypedConfig: mustMarshalAny(otelCfg),
			},
		},
	}
}

// setHeader creates a header mutation rule to append or overwrite a request header.
func (s *xdsServer) setHeader(key, value string) *mutation_rules.HeaderMutation {
	if err := rules.ValidateHeaderName(key); err != nil {
		s.ll.Warn("invalid header name: " + key)

		return &mutation_rules.HeaderMutation{
			Action: &mutation_rules.HeaderMutation_Append{},
		}
	}

	if err := rules.ValidateHeaderValue(value); err != nil {
		s.ll.Warn("invalid header value: " + key)

		return &mutation_rules.HeaderMutation{
			Action: &mutation_rules.HeaderMutation_Append{},
		}
	}

	return &mutation_rules.HeaderMutation{
		Action: &mutation_rules.HeaderMutation_Append{
			Append: &core.HeaderValueOption{
				Header: &core.HeaderValue{
					Key:   key,
					Value: value,
				},
				AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		},
	}
}

// accessLogCfg creates an Envoy file access log configuration in JSON format. Logs include request
// metadata such as start time, method, path, response code, and more.
func accessLogCfg() *anypb.Any {
	fileAccessLog := &fileaccesslog.FileAccessLog{
		Path: "/dev/stdout",
		AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
			LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_JsonFormat{
					JsonFormat: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"start_time":            {Kind: &structpb.Value_StringValue{StringValue: "%START_TIME%"}},
							"method":                {Kind: &structpb.Value_StringValue{StringValue: "%REQ(:METHOD)%"}},
							"path":                  {Kind: &structpb.Value_StringValue{StringValue: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"}},
							"protocol":              {Kind: &structpb.Value_StringValue{StringValue: "%PROTOCOL%"}},
							"response_code":         {Kind: &structpb.Value_StringValue{StringValue: "%RESPONSE_CODE%"}},
							"response_flags":        {Kind: &structpb.Value_StringValue{StringValue: "%RESPONSE_FLAGS%"}},
							"bytes_received":        {Kind: &structpb.Value_StringValue{StringValue: "%BYTES_RECEIVED%"}},
							"bytes_sent":            {Kind: &structpb.Value_StringValue{StringValue: "%BYTES_SENT%"}},
							"duration":              {Kind: &structpb.Value_StringValue{StringValue: "%DURATION%"}},
							"upstream_service_time": {Kind: &structpb.Value_StringValue{StringValue: "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"}}, //nolint: lll
							"x_forwarded_for":       {Kind: &structpb.Value_StringValue{StringValue: "%REQ(X-FORWARDED-FOR)%"}},
							"user_agent":            {Kind: &structpb.Value_StringValue{StringValue: "%REQ(USER-AGENT)%"}},
							"request_id":            {Kind: &structpb.Value_StringValue{StringValue: "%REQ(X-REQUEST-ID)%"}},
							"authority":             {Kind: &structpb.Value_StringValue{StringValue: "%REQ(:AUTHORITY)%"}},
							"upstream_host":         {Kind: &structpb.Value_StringValue{StringValue: "%UPSTREAM_HOST%"}},
							"x_piko_endpoint":       {Kind: &structpb.Value_StringValue{StringValue: "%REQ(X-PIKO-ENDPOINT)%"}},
						},
					},
				},
			},
		},
	}

	return mustMarshalAny(fileAccessLog)
}

func mustMarshalAny(msg proto.Message) *anypb.Any {
	a, err := anypb.New(msg)
	if err != nil {
		// Errors in here should only occur during development
		// and must be avoided at runtime in production.
		panic(err)
	}

	return a
}
