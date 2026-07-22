package args

import (
	"time"

	"github.com/urfave/cli/v3"
)

const (
	category         = "Cache Management"
	maxFailuresName  = "max-failures"
	routeRefreshName = "route-refresh"
)

type Cacher struct {
	MaxFailures  int
	RouteRefresh time.Duration
}

func (f *FlagBuilder) CacherFlags(ca *Cacher) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.IntFlag{
			Category:    category,
			Destination: &ca.MaxFailures,
			Name:        maxFailuresName,
			Sources:     envWrapper("MAX_FAILURES"),
			Usage:       "maximum number of failed refreshes before a reboot",
			Value:       8,
		},
		&cli.DurationFlag{
			Category:    category,
			Destination: &ca.RouteRefresh,
			Name:        routeRefreshName,
			Sources:     envWrapper("ROUTE_REFRESH"),
			Usage:       "duration between refresh of route registry",
			Value:       2 * time.Minute,
		},
	}...)

	return f
}
