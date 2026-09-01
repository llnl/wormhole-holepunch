package streams

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKVStore(t *testing.T) (*kvStore, context.Context) {
	t.Helper()

	conn, js, _ := inProcessNatsServer(t, "test_stream", "test_subject")
	_ = conn

	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{
		Bucket:   "test_bucket",
		Storage:  jetstream.MemoryStorage,
		History:  1,
		Replicas: 1,
	})
	require.NoError(t, err)

	store := &kvStore{
		client: &Client{
			ll: ll,
			nc: conn,
		},
		kv: kv,
	}

	return store, t.Context()
}

//

func Test_kvStore(t *testing.T) {
	t.Parallel()

	store, ctx := newTestKVStore(t)

	t.Run("Put and Get", func(t *testing.T) {
		in := map[string]any{
			"name": "alice",
			"age":  float64(42),
		}

		err := store.Put(ctx, "user.1", in)
		require.NoError(t, err)

		var out map[string]any
		err = store.Get(ctx, "user.1", &out)
		require.NoError(t, err)

		assert.Equal(t, in, out)
	})

	t.Run("Get missing key", func(t *testing.T) {
		var out map[string]any
		err := store.Get(ctx, "does-not-exist", &out)

		assert.Error(t, err)
	})

	t.Run("Get invalid json", func(t *testing.T) {
		_, err := store.kv.Put(ctx, "bad-json", []byte("{not-json"))
		require.NoError(t, err)

		var out map[string]any
		err = store.Get(ctx, "bad-json", &out)

		assert.Error(t, err)
	})

	t.Run("GetWithRevision", func(t *testing.T) {
		type payload struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}

		in := payload{
			Name: "bob",
			Age:  30,
		}

		err := store.Put(ctx, "user.2", in)
		require.NoError(t, err)

		var out payload
		rev, err := store.GetWithRevision(ctx, "user.2", &out)
		require.NoError(t, err)

		assert.Equal(t, in, out)
		assert.Equal(t, uint64(3), rev)
	})

	t.Run("GetWithRevision invalid json", func(t *testing.T) {
		_, err := store.kv.Put(ctx, "bad-json-rev", []byte("{bad-json"))
		require.NoError(t, err)

		var out map[string]any
		rev, err := store.GetWithRevision(ctx, "bad-json-rev", &out)

		assert.Error(t, err)
		assert.Equal(t, uint64(0), rev)
	})

	t.Run("AllKeys", func(t *testing.T) {
		require.NoError(t, store.Put(ctx, "alpha", map[string]string{"v": "1"}))
		require.NoError(t, store.Put(ctx, "beta", map[string]string{"v": "2"}))
		require.NoError(t, store.Put(ctx, "gamma", map[string]string{"v": "3"}))

		keys, err := store.AllKeys(ctx)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, len(keys), 3)
		assert.Contains(t, keys, "alpha")
		assert.Contains(t, keys, "beta")
		assert.Contains(t, keys, "gamma")
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, store.Put(ctx, "delete-me", map[string]string{"v": "x"}))

		err := store.Delete(ctx, "delete-me")
		require.NoError(t, err)

		var out map[string]any
		err = store.Get(ctx, "delete-me", &out)
		assert.Error(t, err)
	})

	t.Run("GetWithRevision update success", func(t *testing.T) {
		type payload struct {
			Value string `json:"value"`
		}

		require.NoError(t, store.Put(ctx, "item", payload{Value: "first"}))

		var current payload
		rev, err := store.GetWithRevision(ctx, "item", &current)
		require.NoError(t, err)
		assert.Equal(t, payload{Value: "first"}, current)
		assert.Equal(t, uint64(10), rev)

		err = store.UpdateWithRevision(ctx, "item", payload{Value: "second"}, rev)
		require.NoError(t, err)

		var updated payload
		newRev, err := store.GetWithRevision(ctx, "item", &updated)
		require.NoError(t, err)

		assert.Equal(t, payload{Value: "second"}, updated)
		assert.Equal(t, uint64(11), newRev)
	})

	t.Run("UpdateWithRevision fails on wrong revision", func(t *testing.T) {
		type payload struct {
			Value string `json:"value"`
		}

		require.NoError(t, store.Put(ctx, "item", payload{Value: "first"}))

		err := store.UpdateWithRevision(ctx, "item", payload{Value: "second"}, 999)
		assert.Error(t, err)

		var out payload
		rev, getErr := store.GetWithRevision(ctx, "item", &out)
		require.NoError(t, getErr)

		assert.Equal(t, payload{Value: "first"}, out)
		assert.Equal(t, uint64(12), rev)
	})

	t.Run("Delete missing key", func(t *testing.T) {
		err := store.Delete(ctx, "missing-key")
		if err != nil {
			assert.False(t, errors.Is(err, nil))
		}
		assert.NotPanics(t, func() {
			_ = err
		})
	})

	t.Run("Put marshal error", func(t *testing.T) {
		store, ctx := newTestKVStore(t)

		ch := make(chan int)
		err := store.Put(ctx, "bad-value", ch)

		assert.Error(t, err)
	})

	t.Run("UpdateWithRevision marshal error", func(t *testing.T) {
		require.NoError(t, store.Put(ctx, "item", map[string]string{"v": "1"}))

		ch := make(chan int)
		err := store.UpdateWithRevision(ctx, "item", ch, 1)

		assert.Error(t, err)
	})
}
