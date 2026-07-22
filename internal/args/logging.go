package args

import (
	"github.com/urfave/cli/v3"
)

const (
	categoryLogging     = "Logging"
	loggingDisableName  = "logging-disable"
	loggingLevelName    = "logging-level"
	loggingLocationName = "logging-location"
	loggingAddressName  = "logging-address"
	loggingNetworkName  = "logging-network"
	otelEndpointName    = "otel-endpoint"
	otelInsecureName    = "otel-insecure"
	otelServiceName     = "otel-service"
)

type Logging struct {
	LoggingDisable  bool
	LoggingLevel    string
	LoggingLocation string
	LoggingAddress  string
	LoggingNetwork  string
	// OtelEndpoint is the target endpoint the collector will connected too
	// (e.g., localhost:4317).
	OtelEndpoint string
	// OtelInsecure disables client transport security.
	OtelInsecure bool
	// OtelService for the target resource.
	OtelService string
}

// LoggingFlags provides the require flags to support system logging. If the defServiceName is
// defined OTEL options will be presented.
func (f *FlagBuilder) LoggingFlags(lo *Logging, defServiceName string) *FlagBuilder {
	base := []cli.Flag{
		&cli.BoolFlag{
			Category:    categoryLogging,
			Destination: &lo.LoggingDisable,
			Name:        loggingDisableName,
			Sources:     envWrapper("LOGGING_DISABLE"),
			Usage:       "Disable all logging except fatal errors",
			Value:       false,
		},
		&cli.StringFlag{
			Category:    categoryLogging,
			Destination: &lo.LoggingLevel,
			Name:        loggingLevelName,
			Sources:     envWrapper("LOGGING_LEVEL"),
			Usage:       "Set the logging level (e.g., debug, info, warn, error)",
			Value:       "info",
		},
		&cli.StringFlag{
			Category:    categoryLogging,
			Destination: &lo.LoggingLocation,
			Name:        loggingLocationName,
			Sources:     envWrapper("LOGGING_LOCATION"),
			Usage:       "Location identifies where logs will be saved, this can be a distinct file or syslog",
			Value:       "stdout",
		},
		&cli.StringFlag{
			Category:    categoryLogging,
			Destination: &lo.LoggingNetwork,
			Name:        loggingNetworkName,
			Sources:     envWrapper("LOGGING_NETWORK"),
			Usage:       "Network specified (e.g., tcp) used for remote log daemon connections",
		},
		&cli.StringFlag{
			Category:    categoryLogging,
			Destination: &lo.LoggingAddress,
			Name:        loggingAddressName,
			Sources:     envWrapper("LOGGING_ADDRESS"),
			Usage:       "Address specified (e.g., localhost:1234) used for remote log daemon connections",
		},
	}

	if defServiceName != "" {
		base = append(base, []cli.Flag{
			&cli.StringFlag{
				Category:    categoryLogging,
				Destination: &lo.OtelEndpoint,
				Name:        otelEndpointName,
				Sources:     envWrapper("OTEL_ENDPOINT"),
				Usage:       "Optional address specified (e.g., localhost:4317) for collector",
			},
			&cli.BoolFlag{
				Category:    categoryLogging,
				Destination: &lo.OtelInsecure,
				Name:        otelInsecureName,
				Sources:     envWrapper("OTEL_INSECURE"),
				Usage:       "Disables client transport security requirement",
				Value:       true,
			},
			&cli.StringFlag{
				Category:    categoryLogging,
				Destination: &lo.OtelService,
				Name:        otelServiceName,
				Sources:     envWrapper("OTEL_SERVICE_NAME"),
				Usage:       "OTEL service name provided to the target resource",
				Value:       defServiceName,
			},
		}...)
	}

	f.Flags = append(f.Flags, base...)

	return f
}
