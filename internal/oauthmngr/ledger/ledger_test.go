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
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

var ll = logs.InitializeDiscard()

const testSessionTTL = time.Hour

// statefulKV is a generated mock_streams.MockKVStore backed by a real map, recording the
// per-key TTL each write carried.
type statefulKV struct {
	*mock_streams.MockKVStore

	mu   *sync.Mutex
	data map[string][]byte
	ttls map[string]time.Duration
}

// ttl returns the TTL of the latest write to key; zero means it carried none.
func (s *statefulKV) ttl(key string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ttls[key]
}

// keys returns the stored keys with the given prefix.
func (s *statefulKV) keys(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string

	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}

	return out
}

// newStatefulMockKVStore wires a generated mock_streams.MockKVStore's methods to a real
// backing map via DoAndReturn, so it behaves like an actual revision-tracking store rather
// than a fixed one-shot expectation. This is needed to exercise the compare-and-swap paths
// in the ledger's transitions, including races across concurrent callers. Like NATS, a plain
// Put or Update clears a key's TTL.
func newStatefulMockKVStore(ctrl *gomock.Controller) *statefulKV {
	var (
		mu       sync.Mutex
		data     = make(map[string][]byte)
		revision = make(map[string]uint64)
		ttls     = make(map[string]time.Duration)
	)

	m := mock_streams.NewMockKVStore(ctrl)

	create := func(k string, v any, ttl time.Duration) error {
		mu.Lock()
		defer mu.Unlock()

		if _, ok := data[k]; ok {
			return streams.ErrKeyExists
		}

		b, err := json.Marshal(v)
		if err != nil {
			return err
		}

		data[k] = b
		revision[k]++
		ttls[k] = ttl

		return nil
	}

	update := func(k string, v any, expectedRevision uint64, ttl time.Duration) error {
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
		ttls[k] = ttl

		return nil
	}

	m.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any) error { return create(k, v, 0) },
	).AnyTimes()

	m.EXPECT().CreateWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any, ttl time.Duration) error { return create(k, v, ttl) },
	).AnyTimes()

	m.EXPECT().UpdateWithRevision(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any, rev uint64) error { return update(k, v, rev, 0) },
	).AnyTimes()

	m.EXPECT().UpdateWithRevisionTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any, rev uint64, ttl time.Duration) error {
			return update(k, v, rev, ttl)
		},
	).AnyTimes()

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
			ttls[k] = 0

			return nil
		},
	).AnyTimes()

	m.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string, v any) error {
			mu.Lock()
			defer mu.Unlock()

			b, ok := data[k]
			if !ok {
				return streams.ErrKeyNotFound
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
				return 0, streams.ErrKeyNotFound
			}

			if err := json.Unmarshal(b, v); err != nil {
				return 0, err
			}

			return revision[k], nil
		},
	).AnyTimes()

	m.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k string) error {
			mu.Lock()
			defer mu.Unlock()

			delete(data, k)
			delete(revision, k)
			delete(ttls, k)

			return nil
		},
	).AnyTimes()

	return &statefulKV{MockKVStore: m, mu: &mu, data: data, ttls: ttls}
}

// failingDeleteKV fails every Delete, leaving records to expire in the store.
type failingDeleteKV struct {
	streams.KVStore
}

func (failingDeleteKV) Delete(context.Context, string) error {
	return errors.New("delete unavailable")
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
	kv            *statefulKV
	ledger        *Store
	nonce         string
	bindingSecret string
	authProof     string
	redeemCode    string
}

func newPendingFixture(t *testing.T) ledgerFixture {
	t.Helper()

	kv := newStatefulMockKVStore(gomock.NewController(t))
	l, err := New(kv, ll, "auth.example.com", 300*time.Second, testSessionTTL)
	require.NoError(t, err)

	flow, err := l.Mint(context.Background(), MintRequest{
		TargetSubdomain: "foo.example.com",
		TargetURL:       "https://foo.example.com/app",
	})
	require.NoError(t, err)

	return ledgerFixture{kv: kv, ledger: l, nonce: flow.Nonce, bindingSecret: flow.BindingSecret}
}

func newLedgerFixture(t *testing.T) ledgerFixture {
	t.Helper()
	f := newPendingFixture(t)
	f.authorize(t)
	return f
}

func (f *ledgerFixture) authorize(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	start, err := f.ledger.BeginCapture(ctx, f.nonce)
	require.NoError(t, err)
	require.NoError(t, f.ledger.AuthorizeCapture(ctx, AuthorizeRequest{
		Nonce: f.nonce, Authority: start.TargetAuthority, BindingSecret: f.bindingSecret, Challenge: start.Challenge,
	}))
	f.authProof = start.AuthProof
}

func (f *ledgerFixture) capture(authority string) (CaptureResponse, error) {
	resp, err := f.ledger.Capture(context.Background(), CaptureRequest{
		Nonce:         f.nonce,
		Authority:     authority,
		SessionCookie: "proxy-session",
		AuthProof:     f.authProof,
	})
	if err == nil {
		f.redeemCode = resp.RedeemCode
	}

	return resp, err
}

func (f ledgerFixture) redeem(authority string) (RedeemResponse, error) {
	code := f.redeemCode
	if code == "" {
		code = "AAAAAAAAAAAAAAAAAAAAAA"
	}

	return f.ledger.Redeem(context.Background(), RedeemRequest{
		Nonce:         f.nonce,
		Authority:     authority,
		BindingSecret: f.bindingSecret,
		Code:          code,
	})
}

func (f ledgerFixture) record(t *testing.T) (flowRecord, bool) {
	t.Helper()

	var rec flowRecord
	err := f.kv.Get(context.Background(), flowKeyPrefix+f.nonce, &rec)

	return rec, err == nil
}

func Test_boundTargetURL(t *testing.T) {
	base := "https://foo.example.com"
	longPath := "/" + strings.Repeat("p", maxTargetURLLen)
	longQuery := "?q=" + strings.Repeat("q", maxTargetURLLen)

	tests := map[string]struct {
		raw  string
		want string
	}{
		"short URL is unchanged":         {raw: base + "/app?x=1#f", want: base + "/app?x=1#f"},
		"oversized query is dropped":     {raw: base + "/app" + longQuery + "#f", want: base + "/app"},
		"oversized path falls back to /": {raw: base + longPath + longQuery, want: base + "/"},
		"unparsable oversized URL":       {raw: "http://[::1" + longPath, want: ""},
		"oversized host cannot fit":      {raw: "https://" + strings.Repeat("a", maxTargetURLLen) + "/app", want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := boundTargetURL(tc.raw)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, len(got), maxTargetURLLen)
		})
	}
}

func Test_Store_BeginCapture_rejectsInvalidFlows(t *testing.T) {
	ctx := context.Background()
	kv := mock_streams.NewMockKVStore(gomock.NewController(t))
	l, err := New(kv, ll, "auth.example.com", time.Minute, testSessionTTL)
	require.NoError(t, err)

	start, err := l.BeginCapture(ctx, "invalid")
	require.ErrorIs(t, err, ErrInvalidRequest)
	assert.Empty(t, start)

	nonce := "AAAAAAAAAAAAAAAAAAAAAA"
	kv.EXPECT().GetWithRevision(ctx, flowKeyPrefix+nonce, gomock.Any()).Return(uint64(0), streams.ErrKeyNotFound)
	start, err = l.BeginCapture(ctx, nonce)
	require.ErrorIs(t, err, ErrFlowUnavailable)
	assert.Empty(t, start)
}

func Test_Store_AuthorizeCapture_rejectsInvalidRequests(t *testing.T) {
	f := newPendingFixture(t)
	ctx := context.Background()
	start, err := f.ledger.BeginCapture(ctx, f.nonce)
	require.NoError(t, err)

	valid := AuthorizeRequest{
		Nonce: f.nonce, Authority: "foo.example.com", BindingSecret: f.bindingSecret, Challenge: start.Challenge,
	}
	for name, mutate := range map[string]func(*AuthorizeRequest){
		"invalid nonce":    func(req *AuthorizeRequest) { req.Nonce = "invalid" },
		"invalid encoding": func(req *AuthorizeRequest) { req.Challenge = "!" },
		"wrong hash size":  func(req *AuthorizeRequest) { req.Challenge = "YQ" },
	} {
		t.Run(name, func(t *testing.T) {
			req := valid
			mutate(&req)
			require.ErrorIs(t, f.ledger.AuthorizeCapture(ctx, req), ErrInvalidRequest)
			rec, ok := f.record(t)
			require.True(t, ok)
			assert.Equal(t, flowPending, rec.State)
		})
	}

	require.NoError(t, f.ledger.AuthorizeCapture(ctx, valid), "invalid requests must not consume the flow")
}

func Test_Store_AuthorizeCapture_bindingFailures(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizeRequest){
		"wrong host":    func(req *AuthorizeRequest) { req.Authority = "bar.example.com" },
		"wrong binding": func(req *AuthorizeRequest) { req.BindingSecret = "other-browser" },
		"empty binding": func(req *AuthorizeRequest) { req.BindingSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPendingFixture(t)
			ctx := context.Background()
			start, err := f.ledger.BeginCapture(ctx, f.nonce)
			require.NoError(t, err)
			req := AuthorizeRequest{
				Nonce: f.nonce, Authority: "foo.example.com", BindingSecret: f.bindingSecret, Challenge: start.Challenge,
			}
			mutate(&req)

			require.ErrorIs(t, f.ledger.AuthorizeCapture(ctx, req), ErrBindingMismatch)
			rec, ok := f.record(t)
			require.True(t, ok)
			assert.Equal(t, flowBurned, rec.State)
			assert.Empty(t, rec.BrowserBindingHash)
			assert.Empty(t, rec.AuthProofHash)

			req.Authority, req.BindingSecret = "foo.example.com", f.bindingSecret
			require.ErrorIs(t, f.ledger.AuthorizeCapture(ctx, req), ErrFlowUnavailable)
		})
	}
}

func Test_Store_Mint(t *testing.T) {
	t.Run("persists a pending flow with only the browser secret hash", func(t *testing.T) {
		f := newPendingFixture(t)
		rec, ok := f.record(t)
		require.True(t, ok)

		assert.True(t, oauthapi.ValidNonce(f.nonce))
		assert.Len(t, f.bindingSecret, 43)
		assert.Equal(t, flowPending, rec.State)
		assert.Equal(t, "foo.example.com", rec.TargetSubdomain)
		assert.Equal(t, "https://foo.example.com/app", rec.TargetURL)
		assert.Equal(t, hashBrowserBindingSecret(f.bindingSecret), rec.BrowserBindingHash)
		assert.Empty(t, rec.SessionCookie)
		assert.WithinDuration(t, time.Now(), rec.CreatedAt, time.Second)
		assert.Equal(t, 300*time.Second, f.kv.ttl(flowKeyPrefix+f.nonce), "flows carry the nonce TTL, not the bucket's")

		b, err := json.Marshal(rec)
		require.NoError(t, err)
		assert.NotContains(t, string(b), f.bindingSecret)
		assert.JSONEq(t, `{
			"state":"pending",
			"target_subdomain":"foo.example.com",
			"target_url":"https://foo.example.com/app",
			"browser_binding_hash":"`+base64.StdEncoding.EncodeToString(rec.BrowserBindingHash)+`",
			"created_at":"`+rec.CreatedAt.Format(time.RFC3339Nano)+`"
		}`, string(b))
	})

	t.Run("store failure returns neither nonce nor secret", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(gomock.NewController(t))
		storeErr := errors.New("store unavailable")
		kv.EXPECT().CreateWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), time.Minute).Return(storeErr)
		l, err := New(kv, ll, "auth.example.com", time.Minute, testSessionTTL)
		require.NoError(t, err)

		result, err := l.Mint(context.Background(), MintRequest{TargetSubdomain: "foo.example.com", TargetURL: "https://foo.example.com/app"})
		require.ErrorIs(t, err, storeErr)
		assert.Empty(t, result)
	})

	t.Run("never overwrites an existing flow", func(t *testing.T) {
		f := newLedgerFixture(t)
		before, ok := f.record(t)
		require.True(t, ok)

		kv := mock_streams.NewMockKVStore(gomock.NewController(t))
		kv.EXPECT().CreateWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, _ string, v any, ttl time.Duration) error {
				// Force a nonce collision against the fixture's pending flow.
				return f.kv.CreateWithTTL(ctx, flowKeyPrefix+f.nonce, v, ttl)
			},
		)
		l, err := New(kv, ll, "auth.example.com", time.Minute, testSessionTTL)
		require.NoError(t, err)

		result, err := l.Mint(context.Background(), MintRequest{
			TargetSubdomain: "bar.example.com", TargetURL: "https://bar.example.com/app",
		})
		require.ErrorIs(t, err, streams.ErrKeyExists)
		assert.Empty(t, result)

		after, ok := f.record(t)
		require.True(t, ok)
		assert.Equal(t, before, after, "the existing flow is untouched")
	})
}

func Test_ledger_fullFlow(t *testing.T) {
	f := newLedgerFixture(t)

	capResp, err := f.capture("auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, "foo.example.com", capResp.TargetSubdomain)
	assert.True(t, oauthapi.ValidNonce(capResp.RedeemCode))
	assert.NotEqual(t, f.nonce, capResp.RedeemCode)

	rec, ok := f.record(t)
	require.True(t, ok)
	assert.Equal(t, flowCaptured, rec.State)

	redResp, err := f.redeem("foo.example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://foo.example.com/app", redResp.TargetURL)
	assert.True(t, validHostSessionHandle(redResp.SessionHandle))
	assert.NotContains(t, redResp.SessionHandle, "proxy-session", "the handle does not expose the oauth2-proxy session")

	_, ok = f.record(t)
	assert.False(t, ok, "redeemed flow is removed")

	session, err := f.ledger.ResolveHostSession(context.Background(), redResp.SessionHandle, "foo.example.com")
	require.NoError(t, err)
	assert.Equal(t, "proxy-session", session)

	keys := f.kv.keys(hostSessionKeyPrefix)
	require.Len(t, keys, 1)
	assert.NotContains(t, keys[0], redResp.SessionHandle, "the store never holds a usable handle")
	assert.Equal(t, testSessionTTL, f.kv.ttl(keys[0]), "host sessions carry the session TTL")
}

func Test_flowTransitionsKeepTheNonceTTL(t *testing.T) {
	f := newPendingFixture(t)
	key := flowKeyPrefix + f.nonce

	f.authorize(t)
	assert.Positive(t, f.kv.ttl(key))
	assert.LessOrEqual(t, f.kv.ttl(key), 300*time.Second, "authorize keeps the remaining nonce lifetime")

	_, err := f.capture("auth.example.com")
	require.NoError(t, err)
	assert.Positive(t, f.kv.ttl(key))
	assert.LessOrEqual(t, f.kv.ttl(key), 300*time.Second, "capture keeps the remaining nonce lifetime")

	t.Run("burned flows keep it too", func(t *testing.T) {
		g := newLedgerFixture(t)
		_, err := g.capture("foo.example.com")
		require.ErrorIs(t, err, ErrBindingMismatch)

		rec, ok := g.record(t)
		require.True(t, ok)
		assert.Equal(t, flowBurned, rec.State)
		assert.Positive(t, g.kv.ttl(flowKeyPrefix+g.nonce))
		assert.LessOrEqual(t, g.kv.ttl(flowKeyPrefix+g.nonce), 300*time.Second,
			"a forged request cannot leave a flow for the session-length bucket TTL")
	})

	t.Run("an almost expired flow is floored at the NATS minimum", func(t *testing.T) {
		assert.Equal(t, minKeyTTL, f.ledger.remainingTTL(time.Now().Add(-299*time.Second-900*time.Millisecond)))
	})
}

func Test_captureRequiresBothBrowserProofs(t *testing.T) {
	f := newPendingFixture(t)
	ctx := context.Background()

	initiator, err := f.ledger.BeginCapture(ctx, f.nonce)
	require.NoError(t, err)
	other, err := f.ledger.BeginCapture(ctx, f.nonce)
	require.NoError(t, err)

	victimCapture := CaptureRequest{
		Nonce: f.nonce, Authority: "auth.example.com", SessionCookie: "other-session", AuthProof: other.AuthProof,
	}
	_, err = f.ledger.Capture(ctx, victimCapture)
	require.ErrorIs(t, err, ErrFlowUnavailable, "auth proof alone cannot capture a session")
	require.NoError(t, f.ledger.AuthorizeCapture(ctx, AuthorizeRequest{
		Nonce: f.nonce, Authority: "foo.example.com", BindingSecret: f.bindingSecret, Challenge: initiator.Challenge,
	}))
	_, err = f.ledger.Capture(ctx, victimCapture)
	require.ErrorIs(t, err, ErrBindingMismatch, "authorization for one browser cannot capture another browser's session")
	_, err = f.redeem("foo.example.com")
	require.ErrorIs(t, err, ErrFlowUnavailable)
	rec, ok := f.record(t)
	require.True(t, ok)
	assert.Empty(t, rec.SessionCookie)
}

func Test_ledger_Capture(t *testing.T) {
	t.Run("malformed requests are rejected without consuming the nonce", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.ledger.Capture(context.Background(), CaptureRequest{Nonce: "bad"})
		require.ErrorIs(t, err, ErrInvalidRequest)

		_, err = f.ledger.Capture(context.Background(), CaptureRequest{Nonce: f.nonce, Authority: "auth.example.com"})
		require.ErrorIs(t, err, ErrInvalidRequest, "missing session cookie")

		rec, _ := f.record(t)
		assert.Equal(t, flowAuthorized, rec.State)
	})

	t.Run("unknown nonce", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.nonce = "AAAAAAAAAAAAAAAAAAAAAA"

		_, err := f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	t.Run("replay is rejected", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.capture("auth.example.com")
		require.NoError(t, err)

		_, err = f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	t.Run("authority mismatch burns the nonce", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.capture("foo.example.com")
		require.ErrorIs(t, err, ErrBindingMismatch)

		rec, ok := f.record(t)
		require.True(t, ok)
		assert.Equal(t, flowBurned, rec.State)
		assert.Empty(t, rec.SessionCookie)

		_, err = f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable, "legitimate retry after burn")
	})

	t.Run("authority port is not significant", func(t *testing.T) {
		f := newLedgerFixture(t)

		_, err := f.capture("auth.example.com:443")
		require.NoError(t, err)

		_, err = f.redeem("foo.example.com:443")
		require.NoError(t, err)
	})

	t.Run("expired nonce is rejected and removed", func(t *testing.T) {
		f := newLedgerFixture(t)

		rec, _ := f.record(t)
		rec.CreatedAt = time.Now().Add(-10 * time.Minute)
		require.NoError(t, f.kv.Put(context.Background(), flowKeyPrefix+f.nonce, rec))

		_, err := f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)

		_, ok := f.record(t)
		assert.False(t, ok)
	})

	t.Run("expired nonce remains rejected if cleanup fails", func(t *testing.T) {
		f := newLedgerFixture(t)
		rec, ok := f.record(t)
		require.True(t, ok)
		rec.CreatedAt = time.Now().Add(-10 * time.Minute)
		require.NoError(t, f.kv.Put(context.Background(), flowKeyPrefix+f.nonce, rec))
		f.ledger.kvStore = failingDeleteKV{f.kv}

		_, err := f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
		_, ok = f.record(t)
		assert.True(t, ok, "failed cleanup leaves the expired flow in the store")
		_, err = f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
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

				if _, err := f.capture("auth.example.com"); err == nil {
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
		_, err := f.capture("auth.example.com")
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

		_, err := f.redeem("foo.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)

		rec, _ := f.record(t)
		assert.Equal(t, flowAuthorized, rec.State, "state is untouched")
	})

	t.Run("replay is rejected", func(t *testing.T) {
		f := captured(t)

		_, err := f.redeem("foo.example.com")
		require.NoError(t, err)

		_, err = f.redeem("foo.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	t.Run("concurrent redeems succeed exactly once", func(t *testing.T) {
		f := captured(t)

		const workers = 20

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			handles []string
		)

		for range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				resp, err := f.redeem("foo.example.com")
				if err == nil {
					mu.Lock()
					handles = append(handles, resp.SessionHandle)
					mu.Unlock()
				} else {
					assert.ErrorIs(t, err, ErrFlowUnavailable)
				}
			}()
		}

		wg.Wait()

		require.Len(t, handles, 1, "the session is released to exactly one caller")
		assert.Len(t, f.kv.keys(hostSessionKeyPrefix), 1, "exactly one host session is issued")
	})

	t.Run("capture after redeem is rejected", func(t *testing.T) {
		f := captured(t)

		_, err := f.redeem("foo.example.com")
		require.NoError(t, err)

		_, err = f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	t.Run("flow left behind by a failed delete cannot be reused", func(t *testing.T) {
		kv := newStatefulMockKVStore(gomock.NewController(t))
		l, err := New(failingDeleteKV{kv}, ll, "auth.example.com", 300*time.Second, testSessionTTL)
		require.NoError(t, err)

		flow, err := l.Mint(context.Background(), MintRequest{
			TargetSubdomain: "foo.example.com", TargetURL: "https://foo.example.com/app",
		})
		require.NoError(t, err)

		f := ledgerFixture{kv: kv, ledger: l, nonce: flow.Nonce, bindingSecret: flow.BindingSecret}
		f.authorize(t)

		_, err = f.capture("auth.example.com")
		require.NoError(t, err)

		_, err = f.redeem("foo.example.com")
		require.NoError(t, err)

		rec, ok := f.record(t)
		require.True(t, ok, "delete failed, so the record remains")
		assert.Equal(t, flowBurned, rec.State)
		assert.Empty(t, rec.SessionCookie)
		assert.Empty(t, rec.BrowserBindingHash)

		_, err = f.redeem("foo.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)

		_, err = f.capture("auth.example.com")
		require.ErrorIs(t, err, ErrFlowUnavailable)
	})

	bindingFailures := map[string]string{
		"different sub-domain":        "bar.example.com",
		"redeemed at the auth domain": "auth.example.com",
	}

	for name, authority := range bindingFailures {
		t.Run(name+" burns the session", func(t *testing.T) {
			f := captured(t)

			_, err := f.redeem(authority)
			require.ErrorIs(t, err, ErrBindingMismatch)

			rec, ok := f.record(t)
			require.True(t, ok)
			assert.Equal(t, flowBurned, rec.State)
			assert.Empty(t, rec.SessionCookie, "captured cookie is discarded")

			_, err = f.redeem("foo.example.com")
			require.ErrorIs(t, err, ErrFlowUnavailable)
		})
	}

	t.Run("missing or incorrect browser proof burns the session", func(t *testing.T) {
		for name, secret := range map[string]string{"missing": "", "incorrect": "other-browser"} {
			t.Run(name, func(t *testing.T) {
				f := captured(t)
				_, err := f.ledger.Redeem(context.Background(), RedeemRequest{
					Nonce:         f.nonce,
					Authority:     "foo.example.com",
					BindingSecret: secret,
					Code:          f.redeemCode,
				})
				require.ErrorIs(t, err, ErrBindingMismatch)

				rec, ok := f.record(t)
				require.True(t, ok)
				assert.Equal(t, flowBurned, rec.State)
				assert.Empty(t, rec.SessionCookie)
			})
		}
	})

	t.Run("the flow nonce and correct browser proof are not enough to redeem", func(t *testing.T) {
		f := captured(t)
		_, err := f.ledger.Redeem(context.Background(), RedeemRequest{
			Nonce:         f.nonce,
			Authority:     "foo.example.com",
			BindingSecret: f.bindingSecret,
			Code:          f.nonce,
		})
		require.ErrorIs(t, err, ErrBindingMismatch)
	})

	t.Run("delete failure does not fail redemption", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kv := mock_streams.NewMockKVStore(ctrl)
		l, err := New(kv, ll, "auth.example.com", 300*time.Second, testSessionTTL)
		require.NoError(t, err)
		nonce := "AAAAAAAAAAAAAAAAAAAAAA"
		bindingSecret, bindingHash, err := newBrowserBindingSecret()
		require.NoError(t, err)

		kv.EXPECT().GetWithRevision(gomock.Any(), flowKeyPrefix+nonce, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ string, v any) (uint64, error) {
				*v.(*flowRecord) = flowRecord{
					State:              flowCaptured,
					TargetSubdomain:    "foo.example.com",
					TargetURL:          "https://foo.example.com/app",
					SessionCookie:      "proxy-session",
					BrowserBindingHash: bindingHash,
					RedeemCodeHash:     hashBrowserBindingSecret(nonce),
					CreatedAt:          time.Now(),
				}

				return 7, nil
			},
		)
		kv.EXPECT().UpdateWithRevisionTTL(gomock.Any(), flowKeyPrefix+nonce, gomock.Any(), uint64(7), gomock.Any()).Return(nil)
		kv.EXPECT().Delete(gomock.Any(), flowKeyPrefix+nonce).Return(errors.New("boom"))
		kv.EXPECT().CreateWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), testSessionTTL).DoAndReturn(
			func(_ context.Context, key string, v any, _ time.Duration) error {
				assert.True(t, strings.HasPrefix(key, hostSessionKeyPrefix))
				assert.Equal(t, "proxy-session", v.(hostSession).ProxySession)
				assert.Equal(t, "foo.example.com", v.(hostSession).Host)

				return nil
			},
		)

		resp, err := l.Redeem(context.Background(), RedeemRequest{
			Nonce:         nonce,
			Authority:     "foo.example.com",
			BindingSecret: bindingSecret,
			Code:          nonce,
		})

		require.NoError(t, err)
		assert.True(t, validHostSessionHandle(resp.SessionHandle))
	})

	t.Run("failing to issue the host session fails redemption", func(t *testing.T) {
		kv := newStatefulMockKVStore(gomock.NewController(t))
		failing := failingSessionCreateKV{kv}
		l, err := New(failing, ll, "auth.example.com", 300*time.Second, testSessionTTL)
		require.NoError(t, err)

		flow, err := l.Mint(context.Background(), MintRequest{
			TargetSubdomain: "foo.example.com", TargetURL: "https://foo.example.com/app",
		})
		require.NoError(t, err)

		f := ledgerFixture{kv: kv, ledger: l, nonce: flow.Nonce, bindingSecret: flow.BindingSecret}
		f.authorize(t)
		_, err = f.capture("auth.example.com")
		require.NoError(t, err)

		resp, err := f.redeem("foo.example.com")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrFlowUnavailable, "a store failure is not a client error")
		assert.Empty(t, resp.SessionHandle)
	})
}

// failingSessionCreateKV fails to create host sessions while storing flows normally.
type failingSessionCreateKV struct {
	streams.KVStore
}

func (f failingSessionCreateKV) CreateWithTTL(ctx context.Context, key string, v any, ttl time.Duration) error {
	if strings.HasPrefix(key, hostSessionKeyPrefix) {
		return errors.New("store full")
	}

	return f.KVStore.CreateWithTTL(ctx, key, v, ttl)
}

func Test_New(t *testing.T) {
	t.Run("valid middleware configuration", func(t *testing.T) {
		l, err := New(mock_streams.NewMockKVStore(gomock.NewController(t)), ll, "auth.example.com", 300*time.Second, testSessionTTL)

		require.NoError(t, err)
		assert.NotNil(t, l)
	})

	invalid := map[string]struct {
		authDomain string
		nonceTTL   time.Duration
		sessionTTL time.Duration
	}{
		"missing auth URL":       {nonceTTL: 300 * time.Second, sessionTTL: time.Hour},
		"zero TTL":               {authDomain: "auth.example.com", sessionTTL: time.Hour},
		"negative TTL":           {authDomain: "auth.example.com", nonceTTL: -time.Second, sessionTTL: time.Hour},
		"sub-second nonce TTL":   {authDomain: "auth.example.com", nonceTTL: 500 * time.Millisecond, sessionTTL: time.Hour},
		"missing session TTL":    {authDomain: "auth.example.com", nonceTTL: 300 * time.Second},
		"sub-second session TTL": {authDomain: "auth.example.com", nonceTTL: 300 * time.Second, sessionTTL: time.Millisecond},
	}

	for name, args := range invalid {
		t.Run(name, func(t *testing.T) {
			l, err := New(nil, ll, args.authDomain, args.nonceTTL, args.sessionTTL)

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
