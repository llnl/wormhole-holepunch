package args

import (
	"time"

	"github.com/urfave/cli/v3"
)

const (
	categoryXDS           = "xDS Control Panel"
	authClusterName       = "auth-cluster"
	authTimeoutName       = "auth-timeout"
	authMaxBytesName      = "auth-max-bytes"
	collectorClusterName  = "collector-cluster"
	collectorEnabledName  = "collector-enabled"
	collectorServiceName  = "collector-service"
	connectTimeoutName    = "connect-timeout"
	enableWebSocketName   = "enable-websocket"
	idleTimeoutName       = "idle-timeout"
	requestTimeoutName    = "request-timeout"
	maxStreamDurationName = "max-stream-duration"
	nodeNameName          = "node-name"
	listenerPortName      = "listener-port"
	listenerAddressName   = "listener-address"
	versionHeaderName     = "version-header"
	xdsClusterName        = "xds-cluster"
)

type XDS struct {
	// AuthCluster for the defined gRPC cluster.
	AuthCluster string
	// AuthTimeout for requests to the auth service.
	AuthTimeout time.Duration
	// AuthMaxReqBytes Sets the maximum size of a message body that the filter will hold in memory.
	AuthMaxBytes uint32
	// ClusterName (XDSName) defines the name for the dynamic resources (envoy.yaml).
	ClusterName string
	// CollectorCluster is the name of the configured cluster that host the Zipkin collector.
	CollectorCluster string
	// CollectorEnabled indicates if tracing should be enabled for requests.
	CollectorEnabled bool
	// CollectorService names the service in the populated resource span.
	CollectorService string
	// ConnectTimeout for new network connections to hosts in the cluster.
	ConnectTimeout time.Duration
	// EnableWebSocket allows for connections to be upgraded to support websockets
	// and all related auth/management requirements.
	EnableWebSocket bool
	// IdleTimeout for every route, disabled when set to zero.
	IdleTimeout time.Duration
	// Timeout is the maximum time Envoy will wait for the request/response exchange
	// to complete, disabled when set to zero.
	RequestTimeout time.Duration
	// MaxStreamDuration a hard cap on how long the stream may exist, regardless of
	// activity. Disabled when set to zero.
	MaxStreamDuration time.Duration
	// NodeName identifies the target Envoy node id.
	NodeName string
	// ListenerPort identifies the port Envoy binds/listens on.
	ListenerPort uint32
	// ListenerAddress identifies the address Envoy binds/listens on.
	ListenerAddress string
	// VersionHeader indicates if the x-holepunch-version header should be injected.
	VersionHeader bool
}

func (f *FlagBuilder) XDSFlags(xds *XDS) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.AuthCluster,
			Name:        authClusterName,
			Sources:     envWrapper("AUTH_CLUSTER"),
			Usage:       "The name of the defined gRPC cluster",
			Value:       "auth_service",
		},
		&cli.DurationFlag{
			Category:    categoryXDS,
			Destination: &xds.AuthTimeout,
			Name:        authTimeoutName,
			Sources:     envWrapper("AUTH_TIMEOUT"),
			Usage:       "Auth service request timeout",
			Value:       5 * time.Second,
		},
		&cli.Uint32Flag{
			Category:    categoryXDS,
			Destination: &xds.AuthMaxBytes,
			Name:        authMaxBytesName,
			Sources:     envWrapper("AUTH_MAX_BYTES"),
			Usage:       "Sets the maximum size of a message body that the filter will hold in memory",
			Value:       8192,
		},
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.ClusterName,
			Name:        xdsClusterName,
			Sources:     envWrapper("XDS_CLUSTER_NAME"),
			Usage:       "Name for the configured xDS cluster (static_resource)",
			Value:       "xds_cluster",
		},
		&cli.DurationFlag{
			Category:    categoryXDS,
			Destination: &xds.ConnectTimeout,
			Name:        connectTimeoutName,
			Sources:     envWrapper("CONNECT_TIMEOUT"),
			Usage:       "The timeout for new network connections to hosts in the cluster",
			Value:       5 * time.Second,
		},
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.CollectorCluster,
			Name:        collectorClusterName,
			Sources:     envWrapper("COLLECTOR_CLUSTER"),
			Usage:       "Name of the configured cluster that host the OTEL collector",
			Value:       "otel_collector",
		},
		&cli.BoolFlag{
			Category:    categoryXDS,
			Destination: &xds.CollectorEnabled,
			Name:        collectorEnabledName,
			Sources:     envWrapper("COLLECTOR_ENABLED"),
			Usage:       "Indicates if tracing should be enabled for requests.",
			Value:       false,
		},
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.CollectorService,
			Name:        collectorServiceName,
			Sources:     envWrapper("COLLECTOR_SERVICE"),
			Usage:       "Name of the configured cluster that host the OTEL collector",
			Value:       "wormhole-envoy",
		},
		&cli.BoolFlag{
			Category:    categoryXDS,
			Destination: &xds.EnableWebSocket,
			Name:        enableWebSocketName,
			Sources:     envWrapper("ENABLE_WEBSOCKET"),
			Usage:       "Allows for connections to be upgraded to support websockets",
		},
		&cli.DurationFlag{
			Category:    categoryXDS,
			Destination: &xds.IdleTimeout,
			Name:        idleTimeoutName,
			Sources:     envWrapper("IDLE_TIMEOUT"),
			Usage:       "Timeout for idle connections",
			Value:       30 * time.Minute,
		},
		&cli.DurationFlag{
			Category:    categoryXDS,
			Destination: &xds.RequestTimeout,
			Name:        requestTimeoutName,
			Sources:     envWrapper("REQUEST_TIMEOUT"),
			Usage:       "Maximum time for the request/response exchange to complete",
			Value:       90 * time.Second,
		},
		&cli.DurationFlag{
			Category:    categoryXDS,
			Destination: &xds.MaxStreamDuration,
			Name:        maxStreamDurationName,
			Sources:     envWrapper("MAX_STREAM_DURATION"),
			Usage:       "Maximum duration for streams established through proxy",
			Value:       12 * time.Hour,
		},
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.NodeName,
			Name:        nodeNameName,
			Sources:     envWrapper("NODE_NAME"),
			Usage:       "Target Envoy node id",
			Value:       "wormhole-node",
		},
		&cli.Uint32Flag{
			Category:    categoryXDS,
			Destination: &xds.ListenerPort,
			Name:        listenerPortName,
			Sources:     envWrapper("LISTENER_PORT"),
			Usage:       "Port Envoy binds/listens on",
			Value:       3128,
		},
		&cli.StringFlag{
			Category:    categoryXDS,
			Destination: &xds.ListenerAddress,
			Name:        listenerAddressName,
			Sources:     envWrapper("LISTENER_ADDRESS"),
			Usage:       "Address Envoy binds/listens on",
			Value:       "0.0.0.0",
		},
		&cli.BoolFlag{
			Category:    categoryXDS,
			Destination: &xds.VersionHeader,
			Name:        versionHeaderName,
			Sources:     envWrapper("VERSION_HEADER"),
			Usage:       "Indicates if the x-holepunch-version header should be injected",
		},
	}...)

	return f
}
