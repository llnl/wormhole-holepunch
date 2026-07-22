package args

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_WebServerFlags(t *testing.T) {
	t.Run("PopulatesDestination - no grpc", func(t *testing.T) {
		var ws WebServer
		fb := &FlagBuilder{}
		fb.WebServerFlags(&ws, "127.0.0.1:8080", false)

		app := &cli.Command{
			Flags: fb.Flags,
			Action: func(_ context.Context, _ *cli.Command) error {
				return nil
			},
		}

		err := app.Run(t.Context(), []string{
			"test",
			"--" + serverAddressName, "0.0.0.0:3128",
		})

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0.0:3128", ws.ServerAddress)
	})
}
