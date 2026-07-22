package holepunch

import (
	"github.com/urfave/cli/v3"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/version"
)

const (
	defaultXDSAddr   = ":8080"
	defaultAuthAddr  = ":8081"
	defaultAdminAddr = ":8082"
)

var (
	cacheArgs    = &args.Cacher{}
	loggingArgs  = &args.Logging{}
	routeRegArgs = &args.RouteRegistry{}
	storageArgs  = &args.Storage{}
	tokenSvcArgs = &args.TokenService{}
	webArgs      = &args.WebServer{}
	xdsArgs      = &args.XDS{}
)

func Tasks() *cli.Command {
	f := args.NewBuilder()

	return &cli.Command{
		Name:    "holepunch",
		Usage:   "Wormhole gateway to manage a dynamic range of proxy targets while enforcing facility requirements.",
		Version: version.GetVersion(),
		Commands: []*cli.Command{
			adminCmd(),
			authCmd(),
			xdsCommand(),
			cacherCmd(),
		},
		Flags: f.Flags,
	}
}

//

func xdsCommand() *cli.Command {
	f := args.NewBuilder().
		LoggingFlags(loggingArgs, "holepunch-xds").
		RouteRegistryFlags(routeRegArgs).
		StorageFlags(storageArgs).
		WebServerFlags(webArgs, defaultXDSAddr, true).
		TokenServiceFlags(tokenSvcArgs).
		XDSFlags(xdsArgs)

	return &cli.Command{
		Name:    "envoy-xds",
		Aliases: []string{"xds"},
		Usage:   "V3 xDS control plane service for Envoy",
		Action:  startXDSCmd,
		Flags:   f.Flags,
	}
}

func authCmd() *cli.Command {
	f := args.NewBuilder().
		LoggingFlags(loggingArgs, "holepunch-auth").
		RouteRegistryFlags(routeRegArgs).
		StorageFlags(storageArgs).
		WebServerFlags(webArgs, defaultAuthAddr, true).
		TokenServiceFlags(tokenSvcArgs)

	return &cli.Command{
		Name:    "envoy-auth",
		Aliases: []string{"auth"},
		Usage:   "External authorization gRPC service for Envoy",
		Action:  startAuthCmd,
		Flags:   f.Flags,
	}
}

func adminCmd() *cli.Command {
	f := args.NewBuilder().
		LoggingFlags(loggingArgs, "holepunch-admin").
		RouteRegistryFlags(routeRegArgs).
		StorageFlags(storageArgs).
		WebServerFlags(webArgs, defaultAdminAddr, false).
		TokenServiceFlags(tokenSvcArgs)

	return &cli.Command{
		Name:   "admin",
		Usage:  "Administrative APIs and helpers",
		Action: startAdminCmd,
		Flags:  f.Flags,
	}
}

func cacherCmd() *cli.Command {
	f := args.NewBuilder().
		LoggingFlags(loggingArgs, "").
		StorageFlags(storageArgs).
		RouteRegistryFlags(routeRegArgs).
		CacherFlags(cacheArgs)

	return &cli.Command{
		Name:   "cacher",
		Usage:  "Cache management service",
		Action: startCacherCmd,
		Flags:  f.Flags,
	}
}
