package ledger

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

var ll = logs.InitializeDiscard()

// newStatefulMockKVStore wires a generated mock_streams.MockKVStore's Get/Put/Delete/
// GetWithRevision/UpdateWithRevision to a real backing map via DoAndReturn, so it behaves
// like an actual revision-tracking store rather than a fixed one-shot expectation. This is
// needed to exercise the compare-and-swap paths in the ledger's
// transitions, including races across concurrent callers.
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
	n1, err := generateNonce()
	require.NoError(t, err)

	n2, err := generateNonce()
	require.NoError(t, err)

	assert.NotEqual(t, n1, n2)
	assert.True(t, oauthapi.ValidNonce(n1))
	assert.Len(t, n1, 22, "128 bits, unpadded url-safe base64")
}

type ledgerFixture struct {
	kv            *mock_streams.MockKVStore
	ledger        *Store
	nonce         string
	bindingSecret string
}

// newLedgerFixture mints a pending flow for 10.0.0.1 targeting foo.example.com.
func newLedgerFixture(t *testing.T) ledgerFixture {
	return newLedgerFixtureWithIPCheck(t, false)
}

func newLedgerFixtureWithIPCheck(t *testing.T, disableClientIPCheck bool) ledgerFixture {
	t.Helper()

	kv := newStatefulMockKVStore(gomock.NewController(t))
	l, err := New(kv, ll, "auth.example.com", 300*time.Second, disableClientIPCheck)
	require.NoError(t, err)

	flow, err := l.Mint(context.Background(), MintRequest{
		ClientIP:        "10.0.0.1",
		TargetScheme:    "https",
		TargetSubdomain: "foo.example.com",
		TargetURL:       "https://foo.example.com/app",
	})
	require.NoError(t, err)

	return ledgerFixture{kv: kv, ledger: l, nonce: flow.Nonce, bindingSecret: flow.BindingSecret}
}

func (f ledgerFixture) capture(clientIP, authority string) (CaptureResponse, error) {
	return f.ledger.Capture(context.Background(), CaptureRequest{
		Nonce:         f.nonce,
		ClientIP:      clientIP,
		Authority:     authority,
		SessionCookie: "proxy-session",
	})
}

func (f ledgerFixture) redeem(clientIP, authority string) (RedeemResponse, error) {
	return f.ledger.Redeem(context.Background(), RedeemRequest{
		Nonce:         f.nonce,
		ClientIP:      clientIP,
		Authority:     authority,
		BindingSecret: f.bindingSecret,
	})
}

func (f ledgerFixture) record(t *testing.T) (flowRecord, bool) {
	t.Helper()

	var rec flowRecord
	err := f.kv.Get(context.Background(), flowKeyPrefix+f.nonce, &rec)

	return rec, err == nil
}

func Test_Store_Mint(t *testing.T) {
	t.Run("persists a pending flow with only the browser secret hash", func(t *testing.T) {
		f := newLedgerFixture(t)
		rec, ok := f.record(t)
		require.True(t, ok)

		assert.True(t, oauthapi.ValidNonce(f.nonce))
		assert.Len(t, f.bindingSecret, 43)
		assert.Equal(t, flowPending, rec.State)
		assert.Equal(t, "10.0.0.1", rec.ClientIP)
		assert.Equal(t, "https", rec.TargetScheme)
		assert.Equal(t, "foo.example.com", rec.TargetSubdomain)
		assert.Equal(t, "https://foo.example.com/app", rec.TargetURL)
		assert.Equal(t, hashBrowserBindingSecret(f.bindingSecret), rec.BrowserBindingHash)
		assert.Empty(t, rec.SessionCookie)
		assert.WithinDuration(t, time.Now(), rec.CreatedAt, time.Second)

		b, err := json.Marshal(rec)
		require.NoError(t, err)
		assert.NotContains(t, string(b), f.bindingSecret)
		assert.JSONEq(t, `{
			"state":"pending",
			"client_ip":"10.0.0.1",
			"target_scheme":"https",
			"target_subdomain":"foo.example.com",
			"target_url":"https://foo.example.com/app",
			"browser_binding_hash":"`+base64.StdEncoding.EncodeToString(rec.BrowserBindingHash)+`",
			"created_at":"`+rec.CreatedAt.Format(time.RFC3339Nano)+`"
		}`, string(b))
	})

	t.Run("store failure returns neither nonce nor secret", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(gomock.NewController(t))
		storeErr := errors.New("store unavailable")
		kv.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(storeErr)
		l, err := New(kv, ll, "auth.example.com", time.Minute, false)
		require.NoError(t, err)

		result, err := l.Mint(context.Background(), MintRequest{
			ClientIP: "10.0.0.1", TargetSubdomain: "foo.example.com", TargetURL: "https://foo.example.com/app",
		})
		require.ErrorIs(t, err, storeErr)
		assert.Empty(t, result)
	})
}

func Test_ledger_fullFlow(t *testing.T) {
	f := newLedgerFixture(t)

	capResp, err := f.capture("10.0.0.1", "auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, "foo.example.com", capResp.TargetSubdomain)
	assert.Equal(t, "https://foo.example.com/-/wormhole/oauthmngr?nonce="+f.nonce, capResp.CallbackURL)

	rec, ok := f.record(t)
	require.True(t, ok)
	assert.Equal(t, flowCaptured, rec.State)

	redResp, err := f.redeem("10.0.0.1", "foo.example.com")
	require.NoError(t, err)
	assert.Equal(t, RedeemResponse{SessionCookie: "proxy-session", TargetURL: "https://foo.example.com/app"}, redResp)

	_, ok = f.record(t)
	assert.False(t, ok, "redeemed flow is removed")
}

func Test_Store_DisableClientIPCheck(t *testing.T) {
	t.Run("allows client IP to change between callbacks", func(t *testing.T) {
		f := newLedgerFixtureWithIPCheck(t, true)

		_, err := f.capture("10.0.0.2", "auth.example.com")
		require.NoError(t, err)

		resp, err := f.redeem("10.0.0.3", "foo.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://foo.example.com/app", resp.TargetURL)
	})

	t.Run("still checks authority", func(t *testing.T) {
		f := newLedgerFixtureWithIPCheck(t, true)

		_, err := f.capture("10.0.0.2", "other.example.com")
		require.ErrorIs(t, err, ErrBindingMismatch)
	})

	t.Run("still checks browser proof", func(t *testing.T) {
		f := newLedgerFixtureWithIPCheck(t, true)
		_, err := f.capture("10.0.0.2", "auth.example.com")
		require.NoError(t, err)

		_, err = f.ledger.Redeem(context.Background(), RedeemRequest{
			Nonce:         f.nonce,
			ClientIP:      "10.0.0.3",
			Authority:     "foo.example.com",
			BindingSecret: "incorrect",
		})
		require.ErrorIs(t, err, ErrBindingMismatch)
	})
}

func Test_ledger_Capture(t *testing.T) {
	t.Run("malformed requests are rejected without consuming the nonce", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.ledger.Capture(context.Background(), CaptureRequest{Nonce: "bad", ClientIP: "10.0.0.1"})
		require.ErrorIs(t, err, ErrInvalidRequest)

		_, err = f.ledger.Capture(context.Background(), CaptureRequest{Nonce: f.nonce, ClientIP: "10.0.0.1", Authority: "auth.example.com"})
		require.ErrorIs(t, err, ErrInvalidRequest, "missing session cookie")

		rec, _ := f.record(t)
		assert.Equal(t, flowPending, rec.State)
	})

	t.Run("unknown nonce", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.nonce = "AAAAAAAAAAAAAAAAAAAAAA"

		_, err := f.capture("10.0.0.1", "auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	t.Run("replay is rejected", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.capture("10.0.0.1", "auth.example.com")
		require.NoError(t, err)

		_, err = f.capture("10.0.0.1", "auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	bindingFailures := map[string][2]string{
		"client IP mismatch": {"10.0.0.2", "auth.example.com"},
		"authority mismatch": {"10.0.0.1", "foo.example.com"},
		"missing client IP":  {"", "auth.example.com"},
	}

	for name, tc := range bindingFailures {
		t.Run(name+" burns the nonce", func(t *testing.T) {
			f := newLedgerFixture(t)

			_, err := f.capture(tc[0], tc[1])
			require.ErrorIs(t, err, ErrBindingMismatch)

			rec, ok := f.record(t)
			require.True(t, ok)
			assert.Equal(t, flowBurned, rec.State)
			assert.Empty(t, rec.SessionCookie)

			_, err = f.capture("10.0.0.1", "auth.example.com")
			require.ErrorIs(t, err, ErrFlowUnavailable, "legitimate retry after burn")
		})
	}

	t.Run("authority port is not significant", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.capture("10.0.0.1", "auth.example.com:443")
		require.NoError(t, err)

		_, err = f.redeem("10.0.0.1", "foo.example.com:443")
		require.NoError(t, err)
	})

	t.Run("callback preserves HTTP and defaults an empty scheme to HTTPS", func(t *testing.T) {
		for _, scheme := range []string{"http", ""} {
			f := newLedgerFixture(t)
			rec, _ := f.record(t)
			rec.TargetScheme = scheme
			require.NoError(t, f.kv.Put(context.Background(), flowKeyPrefix+f.nonce, rec))

			resp, err := f.capture("10.0.0.1", "auth.example.com")
			require.NoError(t, err)
			expectedScheme := scheme
			if expectedScheme == "" {
				expectedScheme = "https"
			}
			assert.Equal(t, expectedScheme+"://foo.example.com"+paths.CallbackPrefix+"?nonce="+f.nonce, resp.CallbackURL)
		}
	})

	t.Run("expired nonce is rejected and removed", func(t *testing.T) {
		f := newLedgerFixture(t)

		rec, _ := f.record(t)
		rec.CreatedAt = time.Now().Add(-10 * time.Minute)
		require.NoError(t, f.kv.Put(context.Background(), flowKeyPrefix+f.nonce, rec))

		_, err := f.capture("10.0.0.1", "auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)

		_, ok := f.record(t)
		assert.False(t, ok)
	})

	t.Run("concurrent captures succeed exactly once", func(t *testing.T) {
		f := newLedgerFixture(t)

		const workers = 20

		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			successes int
		)

		for range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				if _, err := f.capture("10.0.0.1", "auth.example.com"); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		assert.Equal(t, 1, successes)
	})
}

func Test_ledger_Redeem(t *testing.T) {
	captured := func(t *testing.T) ledgerFixture {
		t.Helper()

		f := newLedgerFixture(t)
		_, err := f.capture("10.0.0.1", "auth.example.com")
		require.NoError(t, err)

		return f
	}

	t.Run("malformed nonce", func(t *testing.T) {
		f := captured(t)

		_, err := f.ledger.Redeem(context.Background(), RedeemRequest{Nonce: "bad"})
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("redeem before capture is rejected", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.redeem("10.0.0.1", "foo.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)

		rec, _ := f.record(t)
		assert.Equal(t, flowPending, rec.State, "state is untouched")
	})

	t.Run("replay is rejected", func(t *testing.T) {
		f := captured(t)

		_, err := f.redeem("10.0.0.1", "foo.example.com")
		require.NoError(t, err)

		_, err = f.redeem("10.0.0.1", "foo.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	bindingFailures := map[string][2]string{
		"client IP mismatch":          {"10.0.0.2", "foo.example.com"},
		"different sub-domain":        {"10.0.0.1", "bar.example.com"},
		"redeemed at the auth domain": {"10.0.0.1", "auth.example.com"},
	}

	for name, tc := range bindingFailures {
		t.Run(name+" burns the session", func(t *testing.T) {
			f := captured(t)

			_, err := f.redeem(tc[0], tc[1])
			require.ErrorIs(t, err, ErrBindingMismatch)

			rec, ok := f.record(t)
			require.True(t, ok)
			assert.Equal(t, flowBurned, rec.State)
			assert.Empty(t, rec.SessionCookie, "captured cookie is discarded")

			_, err = f.redeem("10.0.0.1", "foo.example.com")
			require.ErrorIs(t, err, ErrFlowUnavailable)
		})
	}

	t.Run("missing or incorrect browser proof burns the session", func(t *testing.T) {
		for name, secret := range map[string]string{"missing": "", "incorrect": "other-browser"} {
			t.Run(name, func(t *testing.T) {
				f := captured(t)
				_, err := f.ledger.Redeem(context.Background(), RedeemRequest{
					Nonce:         f.nonce,
					ClientIP:      "10.0.0.1",
					Authority:     "foo.example.com",
					BindingSecret: secret,
				})
				require.ErrorIs(t, err, ErrBindingMismatch)

				rec, ok := f.record(t)
				require.True(t, ok)
				assert.Equal(t, flowBurned, rec.State)
				assert.Empty(t, rec.SessionCookie)
			})
		}
	})

	t.Run("delete failure does not fail redemption", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kv := mock_streams.NewMockKVStore(ctrl)
		l, err := New(kv, ll, "auth.example.com", 300*time.Second, false)
		require.NoError(t, err)
		nonce := "AAAAAAAAAAAAAAAAAAAAAA"
		bindingSecret, bindingHash, err := newBrowserBindingSecret()
		require.NoError(t, err)

		kv.EXPECT().GetWithRevision(gomock.Any(), flowKeyPrefix+nonce, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ string, v any) (uint64, error) {
				*v.(*flowRecord) = flowRecord{
					State:              flowCaptured,
					ClientIP:           "10.0.0.1",
					TargetSubdomain:    "foo.example.com",
					TargetURL:          "https://foo.example.com/app",
					SessionCookie:      "proxy-session",
					BrowserBindingHash: bindingHash,
					CreatedAt:          time.Now(),
				}

				return 7, nil
			},
		)
		kv.EXPECT().UpdateWithRevision(gomock.Any(), flowKeyPrefix+nonce, gomock.Any(), uint64(7)).Return(nil)
		kv.EXPECT().Delete(gomock.Any(), flowKeyPrefix+nonce).Return(errors.New("boom"))

		resp, err := l.Redeem(context.Background(), RedeemRequest{
			Nonce:         nonce,
			ClientIP:      "10.0.0.1",
			Authority:     "foo.example.com",
			BindingSecret: bindingSecret,
		})

		require.NoError(t, err)
		assert.Equal(t, "proxy-session", resp.SessionCookie)
	})
}

func Test_New(t *testing.T) {
	t.Run("valid middleware configuration", func(t *testing.T) {
		l, err := New(mock_streams.NewMockKVStore(gomock.NewController(t)), ll, "auth.example.com", 300*time.Second, false)

		require.NoError(t, err)
		assert.NotNil(t, l)
	})

	invalid := map[string]struct {
		authDomain string
		nonceTTL   time.Duration
	}{
		"missing auth URL": {nonceTTL: 300 * time.Second},
		"zero TTL":         {authDomain: "auth.example.com"},
		"negative TTL":     {authDomain: "auth.example.com", nonceTTL: -time.Second},
	}

	for name, args := range invalid {
		t.Run(name, func(t *testing.T) {
			l, err := New(nil, ll, args.authDomain, args.nonceTTL, false)

			require.Error(t, err)
			assert.Nil(t, l)
		})
	}
}

// Test_flowKey_validForNATS guards against keys the real KV store rejects (the mocks accept
// anything), mirroring jetstream's key validation.
func Test_flowKey_validForNATS(t *testing.T) {
	validKey := regexp.MustCompile(`^[-/_=\.a-zA-Z0-9]+$`)

	for range 100 {
		nonce, err := generateNonce()
		require.NoError(t, err)

		key := flowKeyPrefix + nonce

		assert.Regexp(t, validKey, key)
		assert.False(t, strings.HasPrefix(key, ".") || strings.HasSuffix(key, "."), key)
	}
}
