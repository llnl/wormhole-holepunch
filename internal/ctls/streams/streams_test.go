package streams

import (
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/stretchr/testify/assert"
)

func Test_Client_Close(t *testing.T) {
	t.Run("nil client does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			var c *Client
			c.Close()
		})
	})

	t.Run("nil conn does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			c := &Client{}
			c.Close()
		})
	})
}

func Test_buildNatsHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		storage args.Storage
		want    string
	}{
		{
			name: "returns host unchanged when already prefixed with nats scheme",
			storage: args.Storage{
				StorageHost: "nats://localhost:4222",
			},
			want: "nats://localhost:4222",
		}, {
			name: "builds nats url with username and password",
			storage: args.Storage{
				StorageHost:     "localhost:4222",
				StorageUser:     "user",
				StoragePassword: "pass",
			},
			want: "nats://user:pass@localhost:4222",
		}, {
			name: "returns raw host when credentials are missing",
			storage: args.Storage{
				StorageHost: "localhost:4222",
				StorageUser: "user",
			},
			want: "localhost:4222",
		}, {
			name: "returns raw host when both credentials are empty",
			storage: args.Storage{
				StorageHost: "localhost:4222",
			},
			want: "localhost:4222",
		}, {
			name: "returns empty string when host is empty",
			storage: args.Storage{
				StorageHost: "",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildNatsHost(tt.storage)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_cleanHostURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{
			name:   "extracts host from nats url",
			rawURL: "nats://localhost:4222",
			want:   "localhost:4222",
		}, {
			name:   "extracts host from url with credentials",
			rawURL: "nats://user:pass@localhost:4222",
			want:   "localhost:4222",
		}, {
			name:   "returns empty host for raw host without scheme",
			rawURL: "localhost:4222",
			want:   "",
		}, {
			name:   "returns invalid host for malformed url",
			rawURL: "://bad url",
			want:   "invalid-host",
		}, {
			name:   "returns empty string for empty input",
			rawURL: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cleanHostURL(tt.rawURL)
			assert.Equal(t, tt.want, got)
		})
	}
}
