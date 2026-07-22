package args

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_CacherFlags(t *testing.T) {
	var ca Cacher
	fb := &FlagBuilder{}
	fb.CacherFlags(&ca)

	app := &cli.Command{
		Flags: fb.Flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + maxFailuresName, "3",
			"--" + routeRefreshName, "45s",
		})
		assert.NoError(t, err)

		assert.Equal(t, 3, ca.MaxFailures)
		assert.Equal(t, 45*time.Second, ca.RouteRefresh)
	})

	t.Run("UsesDefaultsWhenUnset", func(t *testing.T) {
		var ca2 Cacher
		fb2 := &FlagBuilder{}
		fb2.CacherFlags(&ca2)

		app2 := &cli.Command{
			Flags: fb2.Flags,
			Action: func(_ context.Context, _ *cli.Command) error {
				return nil
			},
		}

		err := app2.Run(t.Context(), []string{"test"})
		assert.NoError(t, err)

		assert.Equal(t, 8, ca2.MaxFailures)
		assert.Equal(t, 2*time.Minute, ca2.RouteRefresh)
	})
}
