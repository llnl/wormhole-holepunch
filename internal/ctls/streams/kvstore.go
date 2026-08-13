package streams

import (
	"context"
	"encoding/json"

	"github.com/nats-io/nats.go/jetstream"
)

type KVStore interface {
	// AllKeys retrieves all keys managed by the cache.
	AllKeys(ctx context.Context) ([]string, error)

	// Delete removes a given from the store.
	Delete(ctx context.Context, k string) error

	// Get retrieves and unmarshalls a given key from the store.
	Get(ctx context.Context, k string, v any) error

	// GetWithRevision retrieves and unmarshalls a given key from the store along with its revision number.
	GetWithRevision(ctx context.Context, k string, v any) (uint64, error)

	// Put marshalls and places it in a store at the given key.
	Put(ctx context.Context, k string, v any) error

	// UpdateWithRevision atomically updates a key only if the revision matches (compare-and-swap).
	UpdateWithRevision(ctx context.Context, k string, v any, revision uint64) error
}

func (c *ctls) AllKeys(ctx context.Context) ([]string, error) {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_AllKeys")
	defer endSpan()

	kw, err := c.kv.WatchAll(ctx, jetstream.IgnoreDeletes())
	if err != nil {
		return []string{}, err
	}
	defer func() { _ = kw.Stop() }()

	keys := make([]string, 0)

	for k := range kw.Updates() {
		if k == nil {
			// initial snapshot finished
			break
		}

		keys = append(keys, k.Key())
	}

	return keys, nil
}

func (c *ctls) Delete(ctx context.Context, k string) error {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_Delete")
	defer endSpan()

	return c.kv.Delete(ctx, k)
}

func (c *ctls) Get(ctx context.Context, k string, v any) error {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_Get")
	defer endSpan()

	entry, err := c.kv.Get(ctx, k)
	if err != nil {
		return err
	}

	return json.Unmarshal(entry.Value(), v)
}

func (c *ctls) GetWithRevision(ctx context.Context, k string, v any) (uint64, error) {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_GetWithRevision")
	defer endSpan()

	entry, err := c.kv.Get(ctx, k)
	if err != nil {
		return 0, err
	}

	if err := json.Unmarshal(entry.Value(), v); err != nil {
		return 0, err
	}

	return entry.Revision(), nil
}

func (c *ctls) Put(ctx context.Context, k string, v any) error {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_Put")
	defer endSpan()

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	_, err = c.kv.Put(ctx, k, b)

	return err
}

func (c *ctls) UpdateWithRevision(ctx context.Context, k string, v any, revision uint64) error {
	ctx, endSpan := c.ll.StartSpan(ctx, "KVStore_UpdateWithRevision")
	defer endSpan()

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	_, err = c.kv.Update(ctx, k, b, revision)

	return err
}
