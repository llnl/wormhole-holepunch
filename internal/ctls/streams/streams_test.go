package streams

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

func Test_Configuration_InitializeRoutes(t *testing.T) {
	waitBetween = time.Microsecond
	maxRetries = 1

	t.Run("no server running", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: nats.DefaultURL,
			Consumer: "test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.Error(t, err)
	})

	_ = localNatsServer(t)

	t.Run("local test srv", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: nats.DefaultURL,
			Consumer: "test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.NoError(t, err)
	})

	t.Run("re-create stream", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: nats.DefaultURL,
			Consumer: "test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.NoError(t, err)
	})

	t.Run("invalid consumer name", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: "nats://localhost:123456",
			Consumer: ">test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.Error(t, err)
	})

	t.Run("invalid port", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: "nats://localhost:123456",
			Consumer: "test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.Error(t, err)
	})

	t.Run("invalid host", func(t *testing.T) {
		storageArgs := args.Storage{
			NatsHost: "nats. ://localhost:123456",
			Consumer: "test",
		}

		_, err := InitializeRoutes(t.Context(), storageArgs, logs.InitializeDiscard())

		assert.Error(t, err)
	})
}
