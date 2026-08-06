package args

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_XDSFlags(t *testing.T) {
	var xds XDS
	fb := &FlagBuilder{}
	fb.XDSFlags(&xds)
	fb.GlobalFlags(&GlobalSettings{})

	app := &cli.Command{
		Flags: fb.Flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("all headers debug", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + allAuthHeadersName, "true",
		})

		assert.ErrorContains(t, err, "--development")
	})

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + develName, "true",
			"--" + authClusterName, "auth_cluster_override",
			"--" + authTimeoutName, "7s",
			"--" + authMaxBytesName, "12345",
			"--" + xdsClusterName, "xds_cluster_override",
			"--" + collectorClusterName, "collector_cluster_override",
			"--" + collectorEnabledName, "true",
			"--" + collectorServiceName, "collector_service_override",
			"--" + connectTimeoutName, "9s",
			"--" + enableWebSocketName, "true",
			"--" + idleTimeoutName, "11m",
			"--" + requestTimeoutName, "13s",
			"--" + maxStreamDurationName, "15m",
			"--" + nodeNameName, "node_override",
			"--" + listenerPortName, "4242",
			"--" + listenerAddressName, "127.0.0.1",
			"--" + versionHeaderName, "true",
			"--" + allAuthHeadersName, "true",
		})

		assert.NoError(t, err)

		assert.Equal(t, "auth_cluster_override", xds.AuthCluster)
		assert.Equal(t, 7*time.Second, xds.AuthTimeout)
		assert.Equal(t, uint32(12345), xds.AuthMaxBytes)
		assert.Equal(t, "xds_cluster_override", xds.ClusterName)
		assert.Equal(t, 9*time.Second, xds.ConnectTimeout)
		assert.Equal(t, "collector_cluster_override", xds.CollectorCluster)
		assert.Equal(t, true, xds.CollectorEnabled)
		assert.Equal(t, "collector_service_override", xds.CollectorService)
		assert.Equal(t, true, xds.EnableWebSocket)
		assert.Equal(t, 11*time.Minute, xds.IdleTimeout)
		assert.Equal(t, 13*time.Second, xds.RequestTimeout)
		assert.Equal(t, 15*time.Minute, xds.MaxStreamDuration)
		assert.Equal(t, "node_override", xds.NodeName)
		assert.Equal(t, uint32(4242), xds.ListenerPort)
		assert.Equal(t, "127.0.0.1", xds.ListenerAddress)
		assert.Equal(t, true, xds.VersionHeader)
		assert.Equal(t, true, xds.AllAuthHeaders)
	})
}
