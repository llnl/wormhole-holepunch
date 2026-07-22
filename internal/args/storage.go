package args

import (
	"os"
	"time"

	"github.com/urfave/cli/v3"
)

const (
	categoryStorage  = "Storage"
	natsHostName     = "nats-host"
	natsReplicasName = "nats-replicas"
	consumerName     = "consumer-name"
	tokensTTLName    = "tokens-ttl"
	maxValueSizeName = "max-value-size"
)

type Storage struct {
	Consumer     string
	MaxValueSize int32
	NatsHost     string
	NatsReplicas int
	TokensTTL    time.Duration
}

func (f *FlagBuilder) StorageFlags(st *Storage) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.StringFlag{
			Category:    categoryStorage,
			Destination: &st.Consumer,
			Name:        consumerName,
			Sources:     envWrapper("CONSUMER_NAME"),
			Usage:       "Consumer/durable name used when subscribing to message streams",
			Value: func() string {
				host, err := os.Hostname()
				if err != nil {
					return "localhost"
				}

				return host
			}(),
		},
		&cli.Int32Flag{
			Category:    categoryStorage,
			Destination: &st.MaxValueSize,
			Name:        maxValueSizeName,
			Sources:     envWrapper("NATS_MAX_VALUE_SIZE"),
			Usage:       "Maximum message size in bytes",
			Value:       8 * 1024 * 1024,
		},
		&cli.StringFlag{
			Category:    categoryStorage,
			Destination: &st.NatsHost,
			Name:        natsHostName,
			Sources:     envWrapper("NATS_HOST"),
			Usage:       "hostname for the target Nats server (e.g., nats://user:password@server:port)",
			Required:    true,
		},
		&cli.IntFlag{
			Category:    categoryStorage,
			Destination: &st.NatsReplicas,
			Name:        natsReplicasName,
			Sources:     envWrapper("NATS_REPLICAS"),
			Usage:       "Number of replicas to keep for the KeyValue store in a clustered environment",
			Value:       1,
		},
		&cli.DurationFlag{
			Category:    categoryStorage,
			Destination: &st.TokensTTL,
			Name:        tokensTTLName,
			Sources:     envWrapper("TOKENS_TTL"),
			Usage:       "Maximum time to live for a token cache entry before refresh required",
			Value:       5 * time.Minute,
		},
	}...)

	return f
}
