package args

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_LoggingFlags(t *testing.T) {
	var lo Logging
	fb := &FlagBuilder{}
	fb.LoggingFlags(&lo, "default-service")

	app := &cli.Command{
		Flags: fb.Flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + loggingDisableName, "true",
			"--" + loggingLevelName, "debug",
			"--" + loggingLocationName, "/var/log/app.log",
			"--" + loggingNetworkName, "tcp",
			"--" + loggingAddressName, "localhost:1234",
			"--" + otelEndpointName, "localhost:4317",
			"--" + otelInsecureName, "true",
			"--" + otelServiceName, "service-override",
		})

		assert.NoError(t, err)

		assert.Equal(t, true, lo.LoggingDisable)
		assert.Equal(t, "debug", lo.LoggingLevel)
		assert.Equal(t, "/var/log/app.log", lo.LoggingLocation)
		assert.Equal(t, "tcp", lo.LoggingNetwork)
		assert.Equal(t, "localhost:1234", lo.LoggingAddress)
		assert.Equal(t, "localhost:4317", lo.OtelEndpoint)
		assert.Equal(t, true, lo.OtelInsecure)
		assert.Equal(t, "service-override", lo.OtelService)
	})
}
