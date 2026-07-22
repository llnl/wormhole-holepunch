package streams

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	natsclient "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

/*
	Mock NATS server, based maintainer feedback in upstream issue:
	https://github.com/nats-io/nats.go/issues/467
*/

func localNatsServer(t *testing.T) *natsserver.Server {
	return natsServerStartup(t, &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      4222,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
}

func inProcessNatsServer(t *testing.T, name, sub string) (*natsclient.Conn, nats.JetStreamContext, *natsserver.Server) {
	opts := &natsserver.Options{
		DontListen: true, // Don't make a TCP socket.
		JetStream:  true,
		StoreDir:   t.TempDir(),
	}

	srv := natsServerStartup(t, opts)

	conn, _ := natsclient.Connect("", natsclient.InProcessServer(srv))
	js, _ := conn.JetStream()

	cfg := &nats.StreamConfig{
		Name:     name,
		Subjects: []string{sub},
		Storage:  nats.FileStorage,
	}

	_, err := js.AddStream(cfg)
	if err != nil {
		assert.NoError(t, err, "adding test stream")
		t.Fail()
	}

	return conn, js, srv
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
