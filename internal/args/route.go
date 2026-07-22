package args

import (
	"time"

	"github.com/urfave/cli/v3"
)

const (
	categoryRouter       = "Route Registry"
	registryHostName     = "registry-host"
	registryFetchName    = "registry-fetch"
	registryDurationName = "registry-duration"
	routePathName        = "route-path"
	staticCfgName        = "static-config"
)

type RouteRegistry struct {
	RegistryHost     string
	RegistryFetch    bool
	RegistryDuration time.Duration
	RoutePath        string
	StaticCfg        string
}

func (f *FlagBuilder) RouteRegistryFlags(rr *RouteRegistry) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.StringFlag{
			Action:      validateURLAction,
			Destination: &rr.RegistryHost,
			Category:    categoryRouter,
			Sources:     envWrapper("REGISTRY_HOST"),
			Name:        registryHostName,
			Usage:       "Target address for all requests to the route registry",
			Required:    true,
		},
		&cli.StringFlag{
			Category:    categoryRouter,
			Destination: &rr.RoutePath,
			Name:        routePathName,
			Sources:     envWrapper("ROUTE_PATH"),
			Usage:       "The path used with the registry service to identify support routes",
			Value:       "/api/v1/route",
		},
		&cli.DurationFlag{
			Category:    categoryRouter,
			Destination: &rr.RegistryDuration,
			Name:        registryDurationName,
			Sources:     envWrapper("REGISTRY_DURATION"),
			Usage:       "The approximate time the system should wait between attempts to update routes from cache",
			Value:       10 * time.Second,
		},
		&cli.BoolFlag{
			Category:    categoryRouter,
			Destination: &rr.RegistryFetch,
			Name:        registryFetchName,
			Sources:     envWrapper("ROUTE_FETCH"),
			Usage:       "Service should attempt to fetch the registry from source during refresh",
			Value:       false,
		},
		&cli.StringFlag{
			Category:    categoryRouter,
			Destination: &rr.StaticCfg,
			Name:        staticCfgName,
			Sources:     envWrapper("STATIC_CONFIG"),
			Usage:       "Provide a static route configuration file, this is a lower priority to the host",
		},
	}...)

	return f
}
