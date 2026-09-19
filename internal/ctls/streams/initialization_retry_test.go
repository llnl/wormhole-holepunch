package streams

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
)

type startingJetStream struct {
	jetstream.JetStream
	failure   error
	remaining int
	attempts  int
	onAttempt func()
}

func (s *startingJetStream) nextError() error {
	s.attempts++
	if s.onAttempt != nil {
		s.onAttempt()
	}
	if s.remaining > 0 {
		s.remaining--
		return s.failure
	}
	return nil
}

func (s *startingJetStream) CreateKeyValue(ctx context.Context, cfg jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
	if err := s.nextError(); err != nil {
		return nil, err
	}
	return s.JetStream.CreateKeyValue(ctx, cfg)
}

func (s *startingJetStream) KeyValue(context.Context, string) (jetstream.KeyValue, error) {
	return nil, s.failure
}

func (s *startingJetStream) CreateStream(ctx context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	if err := s.nextError(); err != nil {
		return nil, err
	}
	return s.JetStream.CreateStream(ctx, cfg)
}

func startupTestClient(t *testing.T, failure error, failures int) (*Client, *startingJetStream) {
	t.Helper()
	nc, js, srv := inProcessNatsServer(t, "startup", "startup")
	t.Cleanup(func() {
		nc.Close()
		srv.Shutdown()
		srv.WaitForShutdown()
	})
	starting := &startingJetStream{JetStream: js, failure: failure, remaining: failures}
	return &Client{
		nc: nc, js: starting, ll: ll,
		storageArgs: args.Storage{NatsReplicas: 1, Consumer: "startup_test"},
	}, starting
}

func Test_InitializeResources_RetryStartup(t *testing.T) {
	oldWait, oldRetries := waitBetween, maxRetries
	waitBetween, maxRetries = time.Millisecond, 2
	t.Cleanup(func() { waitBetween, maxRetries = oldWait, oldRetries })

	initializers := []struct {
		name string
		run  func(*Client, context.Context) (any, error)
	}{
		{"tokens", func(c *Client, ctx context.Context) (any, error) { return c.InitializeTokens(ctx) }},
		{"sessions", func(c *Client, ctx context.Context) (any, error) { return c.InitializeSessions(ctx) }},
		{"routes", func(c *Client, ctx context.Context) (any, error) { return c.InitializeRoutes(ctx) }},
	}

	for _, initializer := range initializers {
		for _, failure := range []error{nats.ErrNoResponders, fmt.Errorf("request: %w", context.DeadlineExceeded)} {
			t.Run(initializer.name+"/"+failure.Error(), func(t *testing.T) {
				client, starting := startupTestClient(t, failure, 2)
				resource, err := initializer.run(client, t.Context())
				require.NoError(t, err)
				require.NotNil(t, resource)
				require.Equal(t, 3, starting.attempts)
			})
		}
	}

	t.Run("permanent error is not retried", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrAuthorization, 10)
		_, err := client.InitializeTokens(t.Context())
		require.ErrorIs(t, err, nats.ErrAuthorization)
		require.Equal(t, 1, starting.attempts)
	})
	t.Run("invalid TTL is not retried", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrNoResponders, 10)
		client.storageArgs.TokensTTL = time.Nanosecond
		_, err := client.InitializeTokens(t.Context())
		require.ErrorContains(t, err, "invalid TTL")
		require.Zero(t, starting.attempts)
	})
	t.Run("retry budget is bounded", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrNoResponders, 10)
		_, err := client.InitializeTokens(t.Context())
		require.ErrorIs(t, err, nats.ErrNoResponders)
		require.Equal(t, 3, starting.attempts)
	})
	t.Run("canceled context does not initialize", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrNoResponders, 10)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := client.InitializeTokens(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, starting.attempts)
	})
	t.Run("cancellation stops retries", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrNoResponders, 10)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		starting.onAttempt = cancel
		_, err := client.InitializeTokens(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, starting.attempts)
	})
	t.Run("caller deadline bounds wait", func(t *testing.T) {
		client, starting := startupTestClient(t, nats.ErrNoResponders, 10)
		waitBetween = time.Hour
		defer func() { waitBetween = time.Millisecond }()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		_, err := client.InitializeTokens(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 1, starting.attempts)
	})
}
