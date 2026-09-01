package args

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_StorageFlags(t *testing.T) {
	var st Storage
	fb := &FlagBuilder{}
	fb.StorageFlags(&st)

	app := &cli.Command{
		Flags: fb.Flags, // StorageFlags appends to f.Flags (not f.flags)
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("populates destination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + consumerName, "consumer-override",
			"--" + maxValueSizeName, "123456",
			"--" + natsReplicasName, "3",
			"--" + tokensTTLName, "42s",
			"--" + storageHostName, "localhost:4222",
			"--" + storageUserName, "user",
			"--" + storagePasswordName, "pass",
		})

		assert.NoError(t, err)

		assert.Equal(t, "consumer-override", st.Consumer)
		assert.Equal(t, int32(123456), st.MaxValueSize)
		assert.Equal(t, 3, st.NatsReplicas)
		assert.Equal(t, 42*time.Second, st.TokensTTL)
		assert.Equal(t, "localhost:4222", st.StorageHost)
		assert.Equal(t, "user", st.StorageUser)
		assert.Equal(t, "pass", st.StoragePassword)
	})

	t.Run("required only", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + storageHostName, "nats://user:pass@localhost:4222",
		})

		assert.NoError(t, err)

		assert.Equal(t, "nats://user:pass@localhost:4222", st.StorageHost)
	})
}
