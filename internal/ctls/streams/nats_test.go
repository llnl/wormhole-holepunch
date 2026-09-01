package streams

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

var ll = logs.InitializeDiscard()

/*
	Mock NATS server, based maintainer feedback in upstream issue:
	https://github.com/nats-io/nats.go/issues/467
*/

func inProcessNatsServer(t *testing.T, name, sub string) (*natsclient.Conn, jetstream.JetStream, *natsserver.Server) {
	opts := &natsserver.Options{
		DontListen: true, // Don't make a TCP socket.
		JetStream:  true,
		StoreDir:   t.TempDir(),
	}

	srv := natsServerStartup(t, opts)

	nc, err := nats.Connect("", natsclient.InProcessServer(srv))
	require.NoError(t, err, "nats.Connect")

	js, err := jetstream.New(nc)
	require.NoError(t, err, "jetstream.New")

	return nc, js, srv
}

func natsServerStartup(t *testing.T, opts *natsserver.Options) *natsserver.Server {
	server, err := natsserver.NewServer(opts)

	if err != nil {
		assert.NoError(t, err, "starting nats test server")
		t.Fail()
	}

	server.Start()

	if !server.ReadyForConnections(time.Second * 5) {
		assert.NoError(t, err, "failed to start server after 5 seconds")
		t.Fail()
	}

	return server
}

func localNatsServer(t *testing.T) *natsserver.Server {
	return natsServerStartup(t, &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      4222,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
}
