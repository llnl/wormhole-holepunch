package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_registry"
)

func mockURLStr(s string) keys.URLString {
	parsed, _ := url.Parse(s)
	hostname := parsed.Hostname()

	return keys.URLString{URL: parsed, Raw: s, Key: strings.TrimPrefix(hostname, "www.")}
}

func mockRegistry(ctrl *gomock.Controller) *mock_registry.MockRouter {
	m := mock_registry.NewMockRouter(ctrl)
	m.EXPECT().FetchProxyControls().Return(map[string]registry.ProxyControls{
		"f4768d90-ee87-42e5-9797-c480eeed94dd": {
			Source:      mockURLStr("http://src-a.holepunch.localwormhole"),
			Destination: mockURLStr("http://dst-a.holepunch.localwormhole"),
			RequestHeaders: map[string]string{
				"foo": "bar",
			},
			PrefixRewrite: "/prefix",
			CommunityID:   "f126807e-4644-42bb-8353-85dcad9e2eb3",
		},
		"bd525ddf-55fa-412d-8c0c-a3bf0350f14a": {
			Source:         mockURLStr("http://src-share.holepunch.localwormhole/foo"),
			Destination:    mockURLStr("http://dst-foo.holepunch.localwormhole"),
			RequestHeaders: map[string]string{},
		},
		"c7e2d03a-59fc-4555-9793-a952c8883d76": {
			Source:         mockURLStr("http://src-share.holepunch.localwormhole/bar"),
			Destination:    mockURLStr("http://dst-bar.holepunch.localwormhole"),
			RequestHeaders: map[string]string{},
		},
		"f4e8a685-bd23-4b7d-9cc8-95359c510316": {
			Source:         mockURLStr("http://src-b.holepunch.localwormhole"),
			Destination:    mockURLStr("http://dst-b.holepunch.localwormhole"),
			RequestHeaders: map[string]string{},
		},
	}).AnyTimes()
	return m
}

func newTestSnapshotServer(t *testing.T, ctrl *gomock.Controller) *xdsServer {
	t.Helper()

	return &xdsServer{
		cache:                 cache.NewSnapshotCache(false, cache.IDHash{}, nil),
		defaultRequestHeaders: establishDefaultRequestHeaders(args.TokenService{SubtokenHeader: "x-subtoken"}),
		ll:                    logs.InitializeDiscard(),
		routeReg:              mockRegistry(ctrl),
		xdsArgs: args.XDS{
			NodeName:        "test-node",
			ListenerAddress: "0.0.0.0",
			ListenerPort:    10000,
			AuthCluster:     "auth",
			AuthTimeout:     200 * time.Millisecond,
			ConnectTimeout:  5 * time.Second,
			IdleTimeout:     10 * time.Second,
			RequestTimeout:  30 * time.Second,
		},
		tokenSvcArgs: args.TokenService{
			TokenHeader:    "x-token",
			SubtokenHeader: "x-subtoken",
		},
	}
}

//

func Test_xdsServer_generateSnapshot(t *testing.T) {
	t.Run("returns no error and snapshot is consistent", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s := newTestSnapshotServer(t, ctrl)

		snap, err := s.generateSnapshot(context.Background())

		require.NoError(t, err)
		require.NotNil(t, snap)
		assert.NoError(t, snap.Consistent())
	})

	t.Run("snapshot contains expected resource counts", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s := newTestSnapshotServer(t, ctrl)

		snap, err := s.generateSnapshot(context.Background())
		require.NoError(t, err)

		// 4 unique destination hosts → 4 clusters.
		assert.Len(t, snap.GetResources(resource.ClusterType), 4)
		// Single route configuration.
		assert.Len(t, snap.GetResources(resource.RouteType), 1)
		// Single listener.
		assert.Len(t, snap.GetResources(resource.ListenerType), 1)
	})

	t.Run("cluster names in snapshot match computed names", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s := newTestSnapshotServer(t, ctrl)

		snap, err := s.generateSnapshot(context.Background())
		require.NoError(t, err)

		clusters := snap.GetResources(resource.ClusterType)
		for name, res := range clusters {
			c := res.(*cluster.Cluster)
			// Cluster.Name must equal LoadAssignment.ClusterName.
			assert.Equal(t, c.GetName(), c.GetLoadAssignment().GetClusterName(),
				"cluster %q: Name and LoadAssignment.ClusterName mismatch", name)
		}
	})

	t.Run("snapshot version is a non-empty hex string", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s := newTestSnapshotServer(t, ctrl)

		snap, err := s.generateSnapshot(context.Background())
		require.NoError(t, err)

		version := snap.GetVersion(resource.ClusterType)
		assert.NotEmpty(t, version)
	})

	t.Run("snapshot version is deterministic for the same inputs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s := newTestSnapshotServer(t, ctrl)

		snap1, err := s.generateSnapshot(context.Background())
		require.NoError(t, err)

		snap2, err := s.generateSnapshot(context.Background())
		require.NoError(t, err)

		assert.Equal(t,
			snap1.GetVersion(resource.ClusterType),
			snap2.GetVersion(resource.ClusterType),
		)
	})
}

func Test_xdsServer_listenerName(t *testing.T) {
	cases := []struct {
		address  string
		port     uint32
		expected string
	}{
		{"0.0.0.0", 8080, "wh_0.0.0.0_8080"},
		{"127.0.0.1", 9090, "wh_127.0.0.1_9090"},
		{"10.0.0.1", 443, "wh_10.0.0.1_443"},
	}

	for _, tc := range cases {
		t.Run(tc.address, func(t *testing.T) {
			s := &xdsServer{
				xdsArgs: args.XDS{ListenerAddress: tc.address, ListenerPort: tc.port},
			}

			assert.Equal(t, tc.expected, s.listenerName())
		})
	}
}

func Test_clusterName(t *testing.T) {
	cases := []struct {
		rawURL   string
		expected string
	}{
		{"http://backend.local:8080", "wh_backend.local_8080"},
		{"http://backend.local", "wh_backend.local_80"},
		{"https://secure.local", "wh_secure.local_443"},
		{"http://multi-part.service.local:9000", "wh_multi-part.service.local_9000"},
	}

	for _, tc := range cases {
		t.Run(tc.rawURL, func(t *testing.T) {
			dst, err := url.Parse(tc.rawURL)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, clusterName(dst))
		})
	}
}

func Test_computeChecksum(t *testing.T) {
	t.Run("deterministic for identical inputs", func(t *testing.T) {
		data := map[string]registry.ProxyControls{
			"route-1": {CommunityID: "abc"},
		}

		assert.Equal(t, computeChecksum(data), computeChecksum(data))
	})

	t.Run("different inputs produce different checksums", func(t *testing.T) {
		a := map[string]registry.ProxyControls{"r1": {CommunityID: "x"}}
		b := map[string]registry.ProxyControls{"r1": {CommunityID: "y"}}

		assert.NotEqual(t, computeChecksum(a), computeChecksum(b))
	})

	t.Run("empty map produces a valid checksum", func(t *testing.T) {
		result := computeChecksum(map[string]registry.ProxyControls{})

		assert.NotEmpty(t, result)
		assert.NotEqual(t, "unknown", result)
	})

	t.Run("result is an 8-character hex string", func(t *testing.T) {
		result := computeChecksum(map[string]registry.ProxyControls{})

		assert.Regexp(t, `^[0-9a-f]{8}$`, result)
	})
}

func Test_normalizeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Short valid string - no sanitization required",
			input:    "valid_name-123",
			expected: "valid_name-123",
		},
		{
			name:     "String with invalid characters - sanitization required",
			input:    "invalid!@#chars<>?",
			expected: "invalidchars",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "String with only invalid characters",
			input:    "!@#$%^&*()<>?",
			expected: "",
		},
		{
			name:  "String longer than 127 characters",
			input: strings.Repeat("a", 128),
			expected: func() string {
				hash := sha256.Sum256([]byte(strings.Repeat("a", 128)))
				return hex.EncodeToString(hash[:])
			}(),
		},
		{
			name:     "String exactly 127 characters - no hashing required",
			input:    strings.Repeat("a", 127),
			expected: strings.Repeat("a", 127),
		},
		{
			name:     "String with mixed valid and invalid characters",
			input:    "partially!valid<>string",
			expected: "partiallyvalidstring",
		},
		{
			name:     "String with underscore, hyphen, and dot",
			input:    "valid.string_name-123",
			expected: "valid.string_name-123",
		},
		{
			name:     "String containing spaces",
			input:    "name with spaces",
			expected: "namewithspaces",
		},
		{
			name:     "String containing numbers only",
			input:    "1234567890",
			expected: "1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeName(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeName(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
