package oauthmngr

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

// newStatefulMockKVStore wires a generated mock_streams.MockKVStore's Get/Put/Delete/
// GetWithRevision/UpdateWithRevision to a real backing map via DoAndReturn, so it behaves
// like an actual revision-tracking store rather than a fixed one-shot expectation. This is
// needed to exercise the compare-and-swap paths in retrieveAndConsumeNonce and
// retrieveAndDeleteSessionData, including races across concurrent callers.
func newStatefulMockKVStore(ctrl *gomock.Controller) *mock_streams.MockKVStore {
	var (
		mu       sync.Mutex
		data     = make(map[string][]byte)
		revision = make(map[string]uint64)
	)

	m := mock_streams.NewMockKVStore(ctrl)

	m.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any) error {
			mu.Lock()
			defer mu.Unlock()

			b, err := json.Marshal(v)
			if err != nil {
				return err
			}

			data[k] = b
			revision[k]++

			return nil
		},
	).AnyTimes()

	m.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any) error {
			mu.Lock()
			defer mu.Unlock()

			b, ok := data[k]
			if !ok {
				return errors.New("key not found")
			}

			return json.Unmarshal(b, v)
		},
	).AnyTimes()

	m.EXPECT().GetWithRevision(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()

			b, ok := data[k]
			if !ok {
				return 0, errors.New("key not found")
			}

			if err := json.Unmarshal(b, v); err != nil {
				return 0, err
			}

			return revision[k], nil
		},
	).AnyTimes()

	m.EXPECT().UpdateWithRevision(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any, expectedRevision uint64) error {
			mu.Lock()
			defer mu.Unlock()

			current, ok := revision[k]
			if !ok {
				return errors.New("key not found")
			}

			if current != expectedRevision {
				return errors.New("revision mismatch")
			}

			b, err := json.Marshal(v)
			if err != nil {
				return err
			}

			data[k] = b
			revision[k]++

			return nil
		},
	).AnyTimes()

	m.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string) error {
			mu.Lock()
			defer mu.Unlock()

			delete(data, k)
			delete(revision, k)

			return nil
		},
	).AnyTimes()

	return m
}

func Test_generateNonce(t *testing.T) {
	t.Run("generates non-empty nonce", func(t *testing.T) {
		nonce, err := generateNonce()

		require.NoError(t, err)
		assert.NotEmpty(t, nonce)
	})

	t.Run("generates unique nonces", func(t *testing.T) {
		nonce1, err1 := generateNonce()
		nonce2, err2 := generateNonce()

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, nonce1, nonce2)
	})

	t.Run("generates nonce with expected minimum length", func(t *testing.T) {
		nonce, err := generateNonce()

		require.NoError(t, err)
		assert.Greater(t, len(nonce), 20, "nonce should be at least 20 characters for 128-bit entropy")
	})

	t.Run("generates URL-safe base64 encoded nonce", func(t *testing.T) {
		nonce, err := generateNonce()

		require.NoError(t, err)
		assert.NotContains(t, nonce, "+")
		assert.NotContains(t, nonce, "/")
	})
}

func Test_storeNonce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	data := nonceData{
		TargetURL:       "https://example.com/callback",
		ClientIP:        "192.168.1.1",
		TargetSubdomain: "app.example.com",
		CreatedAt:       time.Now(),
		Used:            false,
	}
	nonce := "test-nonce-123"

	t.Run("stores nonce successfully", func(t *testing.T) {
		kvStore := mock_streams.NewMockKVStore(ctrl)
		kvStore.EXPECT().Put(gomock.Any(), nonceKeyPrefix+nonce, data).Return(nil)

		err := storeNonce(t.Context(), kvStore, nonce, data)

		require.NoError(t, err)
	})

	t.Run("stores nonce failure", func(t *testing.T) {
		kvStore := mock_streams.NewMockKVStore(ctrl)
		kvStore.EXPECT().Put(gomock.Any(), nonceKeyPrefix+nonce, data).Return(errors.New("error msg"))

		err := storeNonce(t.Context(), kvStore, nonce, data)

		require.Error(t, err)
	})
}

func Test_retrieveAndConsumeNonce(t *testing.T) {
	t.Run("retrieves and marks nonce as used", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "test-nonce-789"
		data := nonceData{
			TargetURL:       "https://example.com/callback",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
			CreatedAt:       time.Now(),
			Used:            false,
		}
		ttl := 300

		require.NoError(t, storeNonce(ctx, kvStore, nonce, data))

		retrieved, err := retrieveAndConsumeNonce(ctx, kvStore, ll, nonce, ttl)

		require.NoError(t, err)
		assert.Equal(t, data.TargetURL, retrieved.TargetURL)
		assert.Equal(t, data.ClientIP, retrieved.ClientIP)
		assert.True(t, retrieved.Used)

		// The stored entry itself should now be marked used, not deleted.
		var stored nonceData
		require.NoError(t, kvStore.Get(ctx, nonceKeyPrefix+nonce, &stored))
		assert.True(t, stored.Used)
	})

	t.Run("returns error when nonce not found", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)

		_, err := retrieveAndConsumeNonce(ctx, kvStore, ll, "nonexistent-nonce", 300)

		require.Error(t, err)
		assert.ErrorIs(t, err, errNonceNotFound)
	})

	t.Run("returns error when nonce already used", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "used-nonce"
		data := nonceData{
			TargetURL:       "https://example.com/callback",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
			CreatedAt:       time.Now(),
			Used:            true,
		}
		ttl := 300

		require.NoError(t, storeNonce(ctx, kvStore, nonce, data))

		_, err := retrieveAndConsumeNonce(ctx, kvStore, ll, nonce, ttl)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce already used")
	})

	t.Run("returns the same not-found error when nonce expired", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "expired-nonce"
		data := nonceData{
			TargetURL:       "https://example.com/callback",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
			CreatedAt:       time.Now().Add(-10 * time.Minute),
			Used:            false,
		}
		ttl := 300

		require.NoError(t, storeNonce(ctx, kvStore, nonce, data))

		_, err := retrieveAndConsumeNonce(ctx, kvStore, ll, nonce, ttl)

		require.Error(t, err)
		// An expired entry is indistinguishable from one that never existed.
		assert.ErrorIs(t, err, errNonceNotFound)

		// The expired entry should have been opportunistically cleaned up.
		var discarded nonceData
		assert.Error(t, kvStore.Get(ctx, nonceKeyPrefix+nonce, &discarded))
	})

	t.Run("exactly one concurrent redemption succeeds", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "race-nonce"
		data := nonceData{
			TargetURL:       "https://example.com/callback",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
			CreatedAt:       time.Now(),
			Used:            false,
		}

		require.NoError(t, storeNonce(ctx, kvStore, nonce, data))

		const attempts = 10

		var wg sync.WaitGroup

		results := make(chan error, attempts)

		for range attempts {
			wg.Go(func() {
				_, err := retrieveAndConsumeNonce(ctx, kvStore, ll, nonce, 300)
				results <- err
			})
		}

		wg.Wait()
		close(results)

		var successes, failures int

		for err := range results {
			if err == nil {
				successes++
				continue
			}

			failures++

			assert.Contains(t, err.Error(), "nonce already used")
		}

		assert.Equal(t, 1, successes, "exactly one concurrent redemption should succeed")
		assert.Equal(t, attempts-1, failures)
	})
}

func Test_validateNonceBinding(t *testing.T) {
	t.Run("validates matching client IP and subdomain", func(t *testing.T) {
		stored := nonceData{
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
		}
		details := requests.RequestDetails{
			Host:     "app.example.com",
			ClientIP: "192.168.1.1",
		}

		err := validateNonceBinding(ll, stored, details)

		require.NoError(t, err)
	})

	t.Run("returns error when client IP does not match", func(t *testing.T) {
		stored := nonceData{
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
		}
		details := requests.RequestDetails{
			Host:     "app.example.com",
			ClientIP: "192.168.1.2",
		}

		err := validateNonceBinding(ll, stored, details)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "client IP does not match")
	})

	t.Run("returns error when subdomain does not match", func(t *testing.T) {
		stored := nonceData{
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
		}
		details := requests.RequestDetails{
			Host:     "different.example.com",
			ClientIP: "192.168.1.1",
		}

		err := validateNonceBinding(ll, stored, details)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "target subdomain does not match")
	})

	t.Run("empty client IP on both sides is treated as a match", func(t *testing.T) {
		stored := nonceData{
			ClientIP:        "",
			TargetSubdomain: "app.example.com",
		}
		details := requests.RequestDetails{
			Host:     "app.example.com",
			ClientIP: "",
		}

		err := validateNonceBinding(ll, stored, details)

		require.NoError(t, err)
	})
}

func Test_storeSessionData(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	data := sessionData{
		SessionCookie: "session-value-abc",
		NonceData: nonceData{
			TargetURL:       "https://example.com/target",
			ClientIP:        "192.168.1.1",
			TargetSubdomain: "app.example.com",
		},
		CreatedAt: time.Now(),
	}
	nonce := "session-nonce-123"

	t.Run("stores session data successfully", func(t *testing.T) {
		kvStore := mock_streams.NewMockKVStore(ctrl)
		kvStore.EXPECT().Put(gomock.Any(), sessionKeyPrefix+nonce, data).Return(nil)

		err := storeSessionData(t.Context(), kvStore, nonce, data)

		require.NoError(t, err)
	})

	t.Run("stores session data failure", func(t *testing.T) {
		kvStore := mock_streams.NewMockKVStore(ctrl)
		kvStore.EXPECT().Put(gomock.Any(), sessionKeyPrefix+nonce, data).Return(errors.New("error msg"))

		err := storeSessionData(t.Context(), kvStore, nonce, data)

		require.Error(t, err)
	})
}

func Test_retrieveAndDeleteSessionData(t *testing.T) {
	t.Run("retrieves and consumes session data", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "session-nonce-456"
		data := sessionData{
			SessionCookie: "session-value-xyz",
			NonceData: nonceData{
				TargetURL:       "https://example.com/target",
				ClientIP:        "192.168.1.1",
				TargetSubdomain: "app.example.com",
			},
			CreatedAt: time.Now(),
		}
		ttl := 300

		require.NoError(t, storeSessionData(ctx, kvStore, nonce, data))

		retrieved, err := retrieveAndDeleteSessionData(ctx, kvStore, ll, nonce, ttl)

		require.NoError(t, err)
		assert.Equal(t, data.SessionCookie, retrieved.SessionCookie)

		var check sessionData
		err = kvStore.Get(ctx, sessionKeyPrefix+nonce, &check)
		assert.Error(t, err, "session data should be deleted")
	})

	t.Run("returns error when session not found", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)

		_, err := retrieveAndDeleteSessionData(ctx, kvStore, ll, "nonexistent-session", 300)

		require.Error(t, err)
		assert.ErrorIs(t, err, errSessionNotFound)
	})

	t.Run("returns error when session already used", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "used-session"
		data := sessionData{
			SessionCookie: "session-value",
			NonceData:     nonceData{},
			CreatedAt:     time.Now(),
			Used:          true,
		}

		require.NoError(t, storeSessionData(ctx, kvStore, nonce, data))

		_, err := retrieveAndDeleteSessionData(ctx, kvStore, ll, nonce, 300)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "session already used")
	})

	t.Run("returns the same not-found error when session expired", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "expired-session"
		data := sessionData{
			SessionCookie: "session-value",
			NonceData:     nonceData{},
			CreatedAt:     time.Now().Add(-10 * time.Minute),
		}
		ttl := 300

		require.NoError(t, storeSessionData(ctx, kvStore, nonce, data))

		_, err := retrieveAndDeleteSessionData(ctx, kvStore, ll, nonce, ttl)

		require.Error(t, err)
		// An expired entry is indistinguishable from one that never existed.
		assert.ErrorIs(t, err, errSessionNotFound)

		// The expired entry should have been opportunistically cleaned up.
		var discarded sessionData
		assert.Error(t, kvStore.Get(ctx, sessionKeyPrefix+nonce, &discarded))
	})

	t.Run("exactly one concurrent redemption succeeds", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "race-session"
		data := sessionData{
			SessionCookie: "session-value",
			NonceData:     nonceData{},
			CreatedAt:     time.Now(),
		}

		require.NoError(t, storeSessionData(ctx, kvStore, nonce, data))

		const attempts = 10

		var wg sync.WaitGroup

		results := make(chan error, attempts)

		for range attempts {
			wg.Go(func() {
				_, err := retrieveAndDeleteSessionData(ctx, kvStore, ll, nonce, 300)
				results <- err
			})
		}

		wg.Wait()
		close(results)

		var successes, failures int

		for err := range results {
			if err == nil {
				successes++
				continue
			}

			failures++

			// The winner deletes the entry right after its CAS succeeds, so a loser can
			// see either "already used" (lost the CAS while the entry still existed) or
			// "not found" (arrived after the winner's cleanup delete), depending on
			// scheduling. Both are correct rejections - what matters is that only one
			// goroutine ever gets the session data back.
			isAlreadyUsed := strings.Contains(err.Error(), "session already used")
			isNotFound := errors.Is(err, errSessionNotFound)
			assert.True(t, isAlreadyUsed || isNotFound, "unexpected error for losing redemption: %v", err)
		}

		assert.Equal(t, 1, successes, "exactly one concurrent redemption should succeed")
		assert.Equal(t, attempts-1, failures)
	})
}

func Test_cleanupNonce(t *testing.T) {
	t.Run("removes nonce from store", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)
		nonce := "cleanup-nonce"
		data := nonceData{
			TargetURL: "https://example.com",
		}

		require.NoError(t, storeNonce(ctx, kvStore, nonce, data))

		cleanupNonce(ctx, kvStore, nonce)

		var retrieved nonceData
		err := kvStore.Get(ctx, nonceKeyPrefix+nonce, &retrieved)
		assert.Error(t, err, "nonce should be deleted")
	})

	t.Run("does not error when nonce does not exist", func(t *testing.T) {
		ctx := t.Context()
		ctrl := gomock.NewController(t)
		kvStore := newStatefulMockKVStore(ctrl)

		cleanupNonce(ctx, kvStore, "nonexistent-nonce")
	})
}
