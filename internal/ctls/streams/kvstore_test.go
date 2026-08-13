package streams

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// inMemKV is an in-memory implementation of KVStore for testing purposes
type inMemKV struct {
	mu       sync.RWMutex
	data     map[string][]byte
	revision map[string]uint64
}

// NewInMemKV creates a new in-memory KV store for testing
func NewInMemKV() KVStore {
	return &inMemKV{
		data:     make(map[string][]byte),
		revision: make(map[string]uint64),
	}
}

func (kv *inMemKV) AllKeys(_ context.Context) ([]string, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	keys := make([]string, 0, len(kv.data))
	for k := range kv.data {
		keys = append(keys, k)
	}

	return keys, nil
}

func (kv *inMemKV) Delete(_ context.Context, k string) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	delete(kv.data, k)
	delete(kv.revision, k)

	return nil
}

func (kv *inMemKV) Get(_ context.Context, k string, v any) error {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	data, exists := kv.data[k]
	if !exists {
		return errors.New("key not found")
	}

	// Unmarshal into v
	return json.Unmarshal(data, v)
}

func (kv *inMemKV) GetWithRevision(_ context.Context, k string, v any) (uint64, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	data, exists := kv.data[k]
	if !exists {
		return 0, errors.New("key not found")
	}

	rev := kv.revision[k]

	// Unmarshal into v
	if err := json.Unmarshal(data, v); err != nil {
		return 0, err
	}

	return rev, nil
}

func (kv *inMemKV) Put(_ context.Context, k string, v any) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	kv.data[k] = data
	kv.revision[k]++

	return nil
}

func (kv *inMemKV) UpdateWithRevision(_ context.Context, k string, v any, expectedRevision uint64) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	// Check if key exists and revision matches
	currentRev, exists := kv.revision[k]
	if !exists {
		return errors.New("key not found")
	}

	if currentRev != expectedRevision {
		return errors.New("revision mismatch")
	}

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	kv.data[k] = data
	kv.revision[k]++

	return nil
}
