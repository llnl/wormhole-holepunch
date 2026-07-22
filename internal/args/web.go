package args

import (
	"time"

	"github.com/urfave/cli/v3"
)

const (
	categoryServer               = "Web Server"
	serverAddressName            = "address"
	grpcKeepaliveTimeName        = "grpc-keepalive-time"
	grpcKeepaliveTimeoutName     = "grpc-keepalive-timeout"
	grpcKeepaliveMinTimeName     = "grpc-keepalive-min-time"
	grpcMaxConcurrentStreamsName = "grpc-max-concurrent-streams"
	maxRecvMsgSizeName           = "grpc-max-msg-recv"
	maxSendMsgSizeName           = "grpc-max-msg-send"
)

type WebServer struct {
	ServerAddress string

	GRPCKeepaliveTime        time.Duration
	GRPCKeepaliveTimeout     time.Duration
	GRPCKeepaliveMinTime     time.Duration
	GRPCMaxConcurrentStreams uint32
	MaxRecvMsgSize           int
	MaxSendMsgSize           int
}

func (f *FlagBuilder) WebServerFlags(ws *WebServer, defAddress string, grpc bool) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.StringFlag{
			Category:    categoryServer,
			Destination: &ws.ServerAddress,
			Name:        serverAddressName,
			Sources:     envWrapper("ADDRESS"),
			Usage:       "The address (host:port) or socket the server should listen on",
			Value:       defAddress,
		},
	}...)

	if grpc {
		f.Flags = append(f.Flags, []cli.Flag{
			&cli.DurationFlag{
				Category:    categoryServer,
				Destination: &ws.GRPCKeepaliveTime,
				Name:        grpcKeepaliveTimeName,
				Sources:     envWrapper("GRPC_KEEPALIVE_TIME"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       30 * time.Second,
			},
			&cli.DurationFlag{
				Category:    categoryServer,
				Destination: &ws.GRPCKeepaliveTime,
				Name:        grpcKeepaliveTimeoutName,
				Sources:     envWrapper("GRPC_KEEPALIVE_TIMEOUT"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       5 * time.Second,
			},
			&cli.DurationFlag{
				Category:    categoryServer,
				Destination: &ws.GRPCKeepaliveTime,
				Name:        grpcKeepaliveMinTimeName,
				Sources:     envWrapper("GRPC_KEEPALIVE_MIN_TIME"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       30 * time.Second,
			},
			&cli.Uint32Flag{
				Category:    categoryServer,
				Destination: &ws.GRPCMaxConcurrentStreams,
				Name:        grpcMaxConcurrentStreamsName,
				Sources:     envWrapper("GRPC_MAX_CONCURRENT_STREAMS"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       1000,
			},
			&cli.IntFlag{
				Category:    categoryServer,
				Destination: &ws.MaxRecvMsgSize,
				Name:        maxRecvMsgSizeName,
				Sources:     envWrapper("GRPC_MAX_RECV_MSG_SIZE"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       10485760, // 10MB
			},
			&cli.IntFlag{
				Category:    categoryServer,
				Destination: &ws.MaxSendMsgSize,
				Name:        maxSendMsgSizeName,
				Sources:     envWrapper("GRPC_MAX_SEND_MSG_SIZE"),
				Usage:       "The address (host:port) or socket the server should listen on",
				Value:       10485760, // 10MB
			},
		}...)
	}

	return f
}
