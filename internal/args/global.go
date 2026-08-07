package args

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

const (
	develName = "development"
)

type GlobalSettings struct {
	// Development indicates that the application is running in development mode. This can be
	// used to enable certain features or behaviors that are only appropriate for development
	// environments, such as verbose logging, debug endpoints, or relaxed security settings.
	Development bool
}

func (f *FlagBuilder) GlobalFlags(gs *GlobalSettings) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.BoolFlag{
			Destination: &gs.Development,
			Name:        develName,
			Sources:     envWrapper("DEVELOPMENT"),
			Usage:       "Enable development mode for Holepunch, some configurations are directly tied to this flag",
		},
	}...)

	return f
}

//

// develActionBool links the proposed flag to a required --development state.
func develActionBool(name string) func(context.Context, *cli.Command, bool) error {
	return func(_ context.Context, cCmd *cli.Command, enabled bool) error {
		if enabled && !cCmd.Bool(develName) {
			return fmt.Errorf(
				"the --%s flag must be set to enable --%s",
				develName,
				name,
			)
		}

		return nil
	}
}

// develActionString links the proposed flag to a required --development state.
func develActionString(name string) func(context.Context, *cli.Command, string) error {
	return func(_ context.Context, cCmd *cli.Command, value string) error {
		if value != "" && !cCmd.Bool(develName) {
			return fmt.Errorf(
				"the --%s flag must be set to enable --%s",
				develName,
				name,
			)
		}

		return nil
	}
}
