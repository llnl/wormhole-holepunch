package args

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_RouteRegistryFlags(t *testing.T) {
	var rr RouteRegistry
	fb := &FlagBuilder{}
	fb.RouteRegistryFlags(&rr)

	app := &cli.Command{
		Flags: fb.Flags, // RouteRegistryFlags appends to f.Flags (not f.flags)
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + registryHostName, "http://registry.example.test:5001",
			"--" + routePathName, "/custom/route/path",
			"--" + registryDurationName, "42s",
			"--" + registryFetchName, "true",
			"--" + staticCfgName, "/etc/app/static-routes.yaml",
		})

		assert.NoError(t, err)

		assert.Equal(t, "http://registry.example.test:5001", rr.RegistryHost)
		assert.Equal(t, "/custom/route/path", rr.RoutePath)
		assert.Equal(t, 42*time.Second, rr.RegistryDuration)
		assert.Equal(t, true, rr.RegistryFetch)
		assert.Equal(t, "/etc/app/static-routes.yaml", rr.StaticCfg)
	})
}
