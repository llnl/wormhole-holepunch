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
	Delete(ctx context.Context, key string) error

	// Get retrieves and unmarshal a given key from the store.
	Get(ctx context.Context, key string, val any) error

	// GetWithRevision retrieves and unmarshal a given key from the store along with its revision number.
	GetWithRevision(ctx context.Context, key string, val any) (uint64, error)

	// Put marshals and places it in a store at the given key.
	Put(ctx context.Context, key string, val any) error

	// UpdateWithRevision atomically updates a key only if the revision matches (compare-and-swap).
	UpdateWithRevision(ctx context.Context, key string, val any, revision uint64) error
}

func (k *kvStore) AllKeys(ctx context.Context) ([]string, error) {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_AllKeys")
	defer endSpan()

	kw, err := k.kv.WatchAll(ctx, jetstream.IgnoreDeletes())
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

func (k *kvStore) Delete(ctx context.Context, key string) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_Delete")
	defer endSpan()

	return k.kv.Delete(ctx, key)
}

func (k *kvStore) Get(ctx context.Context, key string, val any) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_Get")
	defer endSpan()

	entry, err := k.kv.Get(ctx, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(entry.Value(), val)
}

func (k *kvStore) GetWithRevision(ctx context.Context, key string, val any) (uint64, error) {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_GetWithRevision")
	defer endSpan()

	entry, err := k.kv.Get(ctx, key)
	if err != nil {
		return 0, err
	}

	if err := json.Unmarshal(entry.Value(), val); err != nil {
		return 0, err
	}

	return entry.Revision(), nil
}

func (k *kvStore) Put(ctx context.Context, key string, val any) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_Put")
	defer endSpan()

	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = k.kv.Put(ctx, key, b)

	return err
}

func (k *kvStore) UpdateWithRevision(ctx context.Context, key string, val any, revision uint64) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_UpdateWithRevision")
	defer endSpan()

	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = k.kv.Update(ctx, key, b, revision)

	return err
}
