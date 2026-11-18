package streams

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
)

func Test_Client_Close(t *testing.T) {
	t.Run("nil client does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			var c *Client
			c.Close()
		})
	})

	t.Run("nil conn does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			c := &Client{}
			c.Close()
		})
	})
}

func Test_buildNatsHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		storage args.Storage
		want    string
	}{
		{
			name: "returns host unchanged when already prefixed with nats scheme",
			storage: args.Storage{
				StorageHost: "nats://localhost:4222",
			},
			want: "nats://localhost:4222",
		}, {
			name: "builds nats url with username and password",
			storage: args.Storage{
				StorageHost:     "localhost:4222",
				StorageUser:     "user",
				StoragePassword: "pass",
			},
			want: "nats://user:pass@localhost:4222",
		}, {
			name: "returns raw host when credentials are missing",
			storage: args.Storage{
				StorageHost: "localhost:4222",
				StorageUser: "user",
			},
			want: "localhost:4222",
		}, {
			name: "returns raw host when both credentials are empty",
			storage: args.Storage{
				StorageHost: "localhost:4222",
			},
			want: "localhost:4222",
		}, {
			name: "returns empty string when host is empty",
			storage: args.Storage{
				StorageHost: "",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildNatsHost(tt.storage)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_cleanHostURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{
			name:   "extracts host from nats url",
			rawURL: "nats://localhost:4222",
			want:   "localhost:4222",
		}, {
			name:   "extracts host from url with credentials",
			rawURL: "nats://user:pass@localhost:4222",
			want:   "localhost:4222",
		}, {
			name:   "returns empty host for raw host without scheme",
			rawURL: "localhost:4222",
			want:   "",
		}, {
			name:   "returns invalid host for malformed url",
			rawURL: "://bad url",
			want:   "invalid-host",
		}, {
			name:   "returns empty string for empty input",
			rawURL: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cleanHostURL(tt.rawURL)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_Client_InitializeSessions(t *testing.T) {
	newClient := func(t *testing.T) (*Client, jetstream.JetStream) {
		t.Helper()

		nc, js, srv := inProcessNatsServer(t, "sessions", "")
		t.Cleanup(srv.Shutdown)
		t.Cleanup(nc.Close)

		return &Client{js: js, ll: ll, storageArgs: args.Storage{MaxValueSize: 8 << 20}}, js
	}

	bucketConfig := func(t *testing.T, js jetstream.JetStream) jetstream.StreamConfig {
		t.Helper()

		stream, err := js.Stream(context.Background(), "KV_"+sessionBucket)
		require.NoError(t, err)

		info, err := stream.Info(context.Background())
		require.NoError(t, err)

		return info.Config
	}

	t.Run("creates a bounded bucket allowing per-key TTLs", func(t *testing.T) {
		c, js := newClient(t)

		_, err := c.InitializeSessions(context.Background(), 5*time.Minute, 1<<20)
		require.NoError(t, err)

		cfg := bucketConfig(t, js)
		assert.Equal(t, 5*time.Minute, cfg.MaxAge)
		assert.Equal(t, int64(1<<20), cfg.MaxBytes)
		assert.Equal(t, int32(1<<20), cfg.MaxMsgSize, "value size is capped to the bucket size")
		assert.Equal(t, jetstream.DiscardNew, cfg.Discard)
		assert.True(t, cfg.AllowMsgTTL, "per-key TTLs are enabled")
		assert.Equal(t, limitMarkerTTL, cfg.SubjectDeleteMarkerTTL)
	})

	t.Run("per-key TTLs survive compare-and-swap updates", func(t *testing.T) {
		c, _ := newClient(t)
		ctx := context.Background()

		kv, err := c.InitializeSessions(ctx, time.Hour, 1<<20)
		require.NoError(t, err)

		require.NoError(t, kv.CreateWithTTL(ctx, "flow.a", "v1", time.Second))
		require.ErrorIs(t, kv.CreateWithTTL(ctx, "flow.a", "dup", time.Second), ErrKeyExists)

		var got string
		rev, err := kv.GetWithRevision(ctx, "flow.a", &got)
		require.NoError(t, err)
		assert.Equal(t, "v1", got)

		require.Error(t, kv.UpdateWithRevisionTTL(ctx, "flow.a", "stale", rev+1, time.Second), "revision is enforced")
		require.NoError(t, kv.UpdateWithRevisionTTL(ctx, "flow.a", "v2", rev, time.Second))
		require.Error(t, kv.UpdateWithRevisionTTL(ctx, "flow.a", "replay", rev, time.Second), "old revision is rejected")
		require.Error(t, kv.UpdateWithRevisionTTL(ctx, "flow.*", "v", rev, time.Second), "wildcards are not keys")

		require.NoError(t, kv.Get(ctx, "flow.a", &got))
		assert.Equal(t, "v2", got)

		require.Eventually(t, func() bool {
			return errors.Is(kv.Get(ctx, "flow.a", &got), ErrKeyNotFound)
		}, 5*time.Second, 100*time.Millisecond, "the updated key still expires with its TTL, not the bucket's hour")
	})

	t.Run("applies limits to an existing unbounded bucket", func(t *testing.T) {
		c, js := newClient(t)

		_, err := js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{
			Bucket:  sessionBucket,
			Storage: jetstream.MemoryStorage,
			History: 1,
		})
		require.NoError(t, err)

		_, err = c.InitializeSessions(context.Background(), time.Minute, 2<<20)
		require.NoError(t, err)

		cfg := bucketConfig(t, js)
		assert.Equal(t, time.Minute, cfg.MaxAge)
		assert.Equal(t, int64(2<<20), cfg.MaxBytes)
	})

	t.Run("rejects invalid limits", func(t *testing.T) {
		c, _ := newClient(t)

		_, err := c.InitializeSessions(context.Background(), 0, 1<<20)
		require.ErrorContains(t, err, "invalid TTL")

		_, err = c.InitializeSessions(context.Background(), time.Minute, 0)
		require.ErrorContains(t, err, "invalid max bytes")
	})
}
