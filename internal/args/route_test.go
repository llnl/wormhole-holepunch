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
			"--" + redirectAllowListName, "admin.example.test",
			"--" + redirectAllowListName, "https://other.example.test",
		})

		assert.NoError(t, err)

		assert.Equal(t, "http://registry.example.test:5001", rr.RegistryHost)
		assert.Equal(t, "/custom/route/path", rr.RoutePath)
		assert.Equal(t, 42*time.Second, rr.RegistryDuration)
		assert.Equal(t, true, rr.RegistryFetch)
		assert.Equal(t, "/etc/app/static-routes.yaml", rr.StaticCfg)
		assert.Equal(t, []string{"admin.example.test", "https://other.example.test"}, rr.RedirectAllowList)
	})

	t.Run("RedirectAllowListDefaultsEmpty", func(t *testing.T) {
		var localRR RouteRegistry
		localFB := &FlagBuilder{}
		localFB.RouteRegistryFlags(&localRR)

		localApp := &cli.Command{
			Flags: localFB.Flags,
			Action: func(_ context.Context, _ *cli.Command) error {
				return nil
			},
		}

		err := localApp.Run(t.Context(), []string{
			"test",
			"--" + registryHostName, "http://registry.example.test:5001",
		})

		assert.NoError(t, err)
		assert.Empty(t, localRR.RedirectAllowList)
	})
}
