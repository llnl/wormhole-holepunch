package ledger

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

// redeemedFixture completes a flow for foo.example.com and returns the issued handle.
func redeemedFixture(t *testing.T) (ledgerFixture, string) {
	t.Helper()

	f := newLedgerFixture(t)
	_, err := f.capture("auth.example.com")
	require.NoError(t, err)

	resp, err := f.redeem("foo.example.com")
	require.NoError(t, err)

	return f, resp.SessionHandle
}

//

func Test_Store_ResolveHostSession(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves on the host it was issued for, ignoring the default port", func(t *testing.T) {
		f, handle := redeemedFixture(t)

		for _, host := range []string{"foo.example.com", "foo.example.com:443", "FOO.example.com"} {
			session, err := f.ledger.ResolveHostSession(ctx, handle, host)
			require.NoError(t, err, host)
			assert.Equal(t, "proxy-session", session)
		}
	})

	t.Run("a handle taken to another host is rejected and revoked everywhere", func(t *testing.T) {
		f, handle := redeemedFixture(t)

		for _, host := range []string{"bar.example.com", "auth.example.com", "foo.example.com:8443"} {
			t.Run(host, func(t *testing.T) {
				f, handle := redeemedFixture(t)

				_, err := f.ledger.ResolveHostSession(ctx, handle, host)
				require.ErrorIs(t, err, ErrBindingMismatch)
				assert.Empty(t, f.kv.keys(hostSessionKeyPrefix), "the misused session is revoked")

				_, err = f.ledger.ResolveHostSession(ctx, handle, "foo.example.com")
				require.ErrorIs(t, err, ErrSessionUnavailable, "the stolen copy cannot be used at home either")
			})
		}

		session, err := f.ledger.ResolveHostSession(ctx, handle, "foo.example.com")
		require.NoError(t, err, "unrelated sessions are unaffected")
		assert.Equal(t, "proxy-session", session)
	})

	t.Run("expired sessions are rejected even before the store evicts them", func(t *testing.T) {
		f, handle := redeemedFixture(t)
		key := hostSessionKey(handle)

		var rec hostSession
		require.NoError(t, f.kv.Get(ctx, key, &rec))
		rec.ExpiresAt = time.Now().Add(-time.Second)
		require.NoError(t, f.kv.Put(ctx, key, rec))

		_, err := f.ledger.ResolveHostSession(ctx, handle, "foo.example.com")
		require.ErrorIs(t, err, ErrSessionUnavailable)
	})

	t.Run("unknown and malformed handles never reach the store as a lookup", func(t *testing.T) {
		f, handle := redeemedFixture(t)
		other, _, err := newHostSessionHandle()
		require.NoError(t, err)

		for name, h := range map[string]string{
			"unknown":                       other,
			"empty":                         "",
			"legacy raw oauth2-proxy value": "proxy-session",
			"padded":                        handle + "=",
			"truncated":                     handle[:len(handle)-1],
		} {
			_, err := f.ledger.ResolveHostSession(ctx, h, "foo.example.com")
			require.ErrorIs(t, err, ErrSessionUnavailable, name)
		}
	})

	t.Run("store failures are not reported as a missing session", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(gomock.NewController(t))
		kv.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("nats unavailable"))
		l, err := New(kv, ll, "auth.example.com", time.Minute, testSessionTTL)
		require.NoError(t, err)

		handle, _, err := newHostSessionHandle()
		require.NoError(t, err)

		_, err = l.ResolveHostSession(ctx, handle, "foo.example.com")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSessionUnavailable)
		require.NotErrorIs(t, err, ErrBindingMismatch)
	})

	t.Run("revocation failure still rejects the mismatched host", func(t *testing.T) {
		f, handle := redeemedFixture(t)
		f.ledger.kvStore = failingDeleteKV{f.kv}

		session, err := f.ledger.ResolveHostSession(ctx, handle, "bar.example.com")
		require.ErrorIs(t, err, ErrBindingMismatch)
		assert.Empty(t, session)
		assert.Len(t, f.kv.keys(hostSessionKeyPrefix), 1, "failed deletion leaves the session in the store")

		session, err = f.ledger.ResolveHostSession(ctx, handle, "foo.example.com")
		require.NoError(t, err)
		assert.Equal(t, "proxy-session", session)
	})
}

func Test_hostSessionKey_validForNATS(t *testing.T) {
	for range 100 {
		handle, hash, err := newHostSessionHandle()
		require.NoError(t, err)

		key := hostSessionKey(handle)
		assert.Equal(t, hostSessionKeyPrefix+hash, key)
		assert.Regexp(t, `^[-/_=\.a-zA-Z0-9]+$`, key)
		assert.NotContains(t, key, handle)
	}
}
