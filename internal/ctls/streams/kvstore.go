package streams

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// kvKeyRegexp mirrors jetstream's KV key validation, which is not exported.
var kvKeyRegexp = regexp.MustCompile(`^[-/_=\.a-zA-Z0-9]+$`)

// ErrKeyExists is returned by KVStore.Create when the key already holds a value.
var ErrKeyExists = jetstream.ErrKeyExists

// ErrKeyNotFound is returned by KVStore reads when the key holds no value (or has expired).
var ErrKeyNotFound = jetstream.ErrKeyNotFound

type KVStore interface {
	// AllKeys retrieves all keys managed by the cache.
	AllKeys(ctx context.Context) ([]string, error)

	// Create marshals and places it in a store at the given key only if the key does not
	// already hold a value; otherwise it returns an error matching ErrKeyExists.
	Create(ctx context.Context, key string, val any) error

	// CreateWithTTL is Create with a per-key TTL, after which NATS removes the key. The bucket
	// must allow per-key TTLs (see InitializeSessions).
	CreateWithTTL(ctx context.Context, key string, val any, ttl time.Duration) error

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

	// UpdateWithRevisionTTL is UpdateWithRevision that also sets the key's TTL. A plain update
	// clears any per-key TTL, leaving the key to the bucket's TTL instead.
	UpdateWithRevisionTTL(ctx context.Context, key string, val any, revision uint64, ttl time.Duration) error
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

func (k *kvStore) Create(ctx context.Context, key string, val any) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_Create")
	defer endSpan()

	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = k.kv.Create(ctx, key, b)

	return err
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

func (k *kvStore) CreateWithTTL(ctx context.Context, key string, val any, ttl time.Duration) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_CreateWithTTL")
	defer endSpan()

	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = k.kv.Create(ctx, key, b, jetstream.KeyTTL(ttl))

	return err
}

// UpdateWithRevisionTTL publishes the compare-and-swap update jetstream's KeyValue.Update
// performs, adding the per-message TTL header it omits. It assumes a bucket in the default
// JetStream domain that is neither a mirror nor sourced, as created by this package.
func (k *kvStore) UpdateWithRevisionTTL(
	ctx context.Context,
	key string,
	val any,
	revision uint64,
	ttl time.Duration,
) error {
	ctx, endSpan := k.client.ll.StartSpan(ctx, "KVStore_UpdateWithRevisionTTL")
	defer endSpan()

	if !validKVKey(key) {
		return jetstream.ErrInvalidKey
	}

	if ttl <= 0 {
		return errors.New("update TTL must be positive")
	}

	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	msg := &nats.Msg{
		Subject: "$KV." + k.kv.Bucket() + "." + key,
		Header:  nats.Header{},
		Data:    b,
	}

	_, err = k.client.js.PublishMsg(ctx, msg,
		jetstream.WithExpectLastSequencePerSubject(revision),
		jetstream.WithMsgTTL(ttl),
	)

	return err
}

func validKVKey(key string) bool {
	return kvKeyRegexp.MatchString(key) && !strings.HasPrefix(key, ".") && !strings.HasSuffix(key, ".")
}
