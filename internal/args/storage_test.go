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

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + consumerName, "consumer-override",
			"--" + maxValueSizeName, "123456",
			"--" + natsHostName, "nats://user:pass@localhost:4222",
			"--" + natsReplicasName, "3",
			"--" + tokensTTLName, "42s",
		})

		assert.NoError(t, err)

		assert.Equal(t, "consumer-override", st.Consumer)
		assert.Equal(t, int32(123456), st.MaxValueSize)
		assert.Equal(t, "nats://user:pass@localhost:4222", st.NatsHost)
		assert.Equal(t, 3, st.NatsReplicas)
		assert.Equal(t, 42*time.Second, st.TokensTTL)
	})
}
