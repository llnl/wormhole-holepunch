// Package streams provides helper functions and supported interfaces designed to
// more easily interact with the support Pub/Sub system.
package streams

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

const (
	routesSubject = "holepunch.routes"
	routesStream  = "HOLEPUNCH_ROUTES"
	tokenBucket   = "holepunch_tokens"
)

var (
	waitBetween = 5 * time.Second
	maxRetries  = 5
)

type Configuration struct {
	Host         string
	ConsumerName string
	Replicas     int
	TokensTTL    time.Duration
	MaxValueSize int32
}

type ctls struct {
	consumer   jetstream.Consumer
	js         jetstream.JetStream
	kv         jetstream.KeyValue
	ll         logs.Logger
	nc         *nats.Conn
	stream     jetstream.Stream
	streamName string
	subject    string
}

// InitializeTokens starts the NATS connection and support key/value store
// for token management.
func InitializeTokens(ctx context.Context, storageArgs args.Storage, ll logs.Logger) (KVStore, error) {
	ll.Info("establishing token key/value store targeting " + cleanHostURL(storageArgs.NatsHost))

	sc, err := connect(storageArgs, ll, routesSubject, routesStream)
	if err != nil {
		return nil, err
	}

	// Create or retrieve a Key-Value store bucket
	kv, err := sc.js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       tokenBucket,
		Replicas:     storageArgs.NatsReplicas,
		Storage:      jetstream.MemoryStorage,
		MaxValueSize: storageArgs.MaxValueSize,
		History:      1,
		TTL:          storageArgs.TokensTTL,
	})
	if err != nil {
		// If bucket exists, just bind to it
		kv, err = sc.js.KeyValue(ctx, tokenBucket)
		if err != nil {
			return nil, fmt.Errorf("failed to bind to KeyValue store: %w", err)
		}
	}

	sc.kv = kv

	return sc, nil
}

// InitializeRoutes starts the NATS connection and context to both publish/subscribe
// messages relating to route management.
func InitializeRoutes(ctx context.Context, storageArgs args.Storage, ll logs.Logger) (PubSub, error) {
	ll.Info("establishing routes stream targeting " + cleanHostURL(storageArgs.NatsHost))

	sc, err := connect(storageArgs, ll, routesSubject, routesStream)
	if err != nil {
		return nil, err
	}

	streamCfg := jetstream.StreamConfig{
		Name:        sc.streamName,
		Replicas:    storageArgs.NatsReplicas,
		Subjects:    []string{sc.subject},
		Storage:     jetstream.MemoryStorage, // In-memory stream
		MaxMsgs:     1,                       // Retain only the last message
		Discard:     jetstream.DiscardOld,    // Discard old messages when limit is reached
		AllowDirect: true,                    // Enable direct get for efficiency
	}

	err = sc.addStream(ctx, streamCfg)
	if err != nil {
		return nil, err
	}

	// Create a durable consumer that doesn't delete messages on acknowledgement
	// By using AckExplicitPolicy with MaxDeliver=-1, messages remain in the stream
	// even after being acknowledged, allowing multiple consumers to read the same message
	consumer, err := sc.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       storageArgs.Consumer,
		AckPolicy:     jetstream.AckExplicitPolicy, // Require explicit acknowledgement
		MaxDeliver:    -1,                          // Unlimited redelivery (messages not deleted)
		DeliverPolicy: jetstream.DeliverLastPolicy, // Always start with the last message
		AckWait:       15 * time.Second,            // Wait time before redelivery
		FilterSubject: sc.subject,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating consumer: %w", err)
	}

	sc.consumer = consumer

	return sc, nil
}

//

func connect(
	storageArgs args.Storage,
	ll logs.Logger,
	subject, streamName string,
) (*ctls, error) {
	nc, err := nats.Connect(
		storageArgs.NatsHost,
		nats.MaxReconnects(maxRetries),
		nats.ReconnectWait(waitBetween),
		nats.Timeout(10*time.Second), // per-attempt dial/connect timeout
		nats.RetryOnFailedConnect(true),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			ll.Warnf("NATS disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			ll.Infof("NATS reconnected to %s", cleanHostURL(storageArgs.NatsHost))
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			ll.Errorf("NATS connection closed: %v", nc.LastError())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("error connecting to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("error creating JetStream context: %w", err)
	}

	return &ctls{
		js:         js,
		ll:         ll,
		nc:         nc,
		subject:    subject,
		streamName: streamName,
	}, nil
}

func (c *ctls) addStream(ctx context.Context, streamCfg jetstream.StreamConfig) error {
	stream, err := c.js.CreateStream(ctx, streamCfg)
	if err != nil {
		if errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
			c.ll.Debugf("stream %s already exists, skipping creation", c.streamName)
		} else {
			return err
		}
	}

	c.stream = stream

	return nil
}

func cleanHostURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "invalid-host"
	}

	return parsedURL.Host
}
