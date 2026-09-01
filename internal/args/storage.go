package args

import (
	"os"
	"time"

	"github.com/urfave/cli/v3"
)

const (
	categoryStorage     = "Storage"
	consumerName        = "consumer-name"
	maxValueSizeName    = "max-value-size"
	natsReplicasName    = "nats-replicas"
	tokensTTLName       = "tokens-ttl"
	storageHostName     = "storage-host"
	storageUserName     = "storage-user"
	storagePasswordName = "storage-password"
)

type Storage struct {
	Consumer        string
	MaxValueSize    int32
	NatsReplicas    int
	TokensTTL       time.Duration
	StorageHost     string
	StorageUser     string
	StoragePassword string
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
			Usage:       "Maximum time to live for a token/session related cache before refresh required",
			Value:       5 * time.Minute,
		},
		&cli.StringFlag{
			Category:    categoryStorage,
			Destination: &st.StorageHost,
			Name:        storageHostName,
			Sources:     envWrapper("STORAGE_HOST"),
			Usage:       "hostname for the target storage server (e.g., server:port)",
			Required:    true,
		},
		&cli.StringFlag{
			Category:    categoryStorage,
			Destination: &st.StorageUser,
			Name:        storageUserName,
			Sources:     envWrapper("STORAGE_USER"),
			Usage:       "username for the target storage server",
			Required:    false,
		},
		&cli.StringFlag{
			Category:    categoryStorage,
			Destination: &st.StoragePassword,
			Name:        storagePasswordName,
			Sources:     envWrapper("STORAGE_PASSWORD"),
			Usage:       "password for the target storage server",
			Required:    false,
		},
	}...)

	return f
}
