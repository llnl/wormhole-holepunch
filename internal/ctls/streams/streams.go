// Package streams provides helper functions and supported interfaces designed to
// more easily interact with the support Pub/Sub system.
package streams

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

const (
	routesSubject  = "holepunch.routes"
	routesStream   = "HOLEPUNCH_ROUTES"
	sessionBucket  = "holepunch_sessions"
	tokenBucket    = "holepunch_tokens"
	minKVTTL       = 100 * time.Millisecond
	limitMarkerTTL = time.Second
	natsHostPrefix = "nats://"
)

var (
	waitBetween = 5 * time.Second
	maxRetries  = 5
)

// Client owns the shared NATS and JetStream connection for all stream resources
// used by a single process.
type Client struct {
	js          jetstream.JetStream
	ll          logs.Logger
	logHost     string
	nc          *nats.Conn
	tarHost     string
	storageArgs args.Storage
}

// kvStore is a single KeyValue bucket handle backed by a shared Client.
type kvStore struct {
	client *Client
	kv     jetstream.KeyValue
}

// pubsub is a single stream/consumer handle backed by a shared Client.
type pubsub struct {
	client     *Client
	consumer   jetstream.Consumer
	stream     jetstream.Stream
	streamName string
	subject    string
}

// Connect establishes the shared NATS and JetStream client used to initialize
// one or more KV buckets and/or streams from the same process.
func Connect(storageArgs args.Storage, ll logs.Logger) (*Client, error) {
	tarHost := buildNatsHost(storageArgs)
	logHost := cleanHostURL(tarHost)

	nc, err := nats.Connect(
		tarHost,
		nats.MaxReconnects(maxRetries),
		nats.ReconnectWait(waitBetween),
		nats.Timeout(10*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			ll.Warnf("NATS disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			ll.Infof("NATS reconnected to %s", logHost)
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
		nc.Close()
		return nil, fmt.Errorf("error creating JetStream context: %w", err)
	}

	return &Client{
		js:          js,
		ll:          ll,
		logHost:     logHost,
		nc:          nc,
		tarHost:     tarHost,
		storageArgs: storageArgs,
	}, nil
}

// Close shuts down the shared NATS connection.
func (c *Client) Close() {
	if c == nil || c.nc == nil || c.nc.IsClosed() {
		return
	}

	c.nc.Close()
}

// InitializeTokens starts or binds the token KeyValue store using the shared Client.
func (c *Client) InitializeTokens(ctx context.Context) (KVStore, error) {
	return c.initializeKV(ctx, tokenBucket)
}

// InitializeSessions starts or binds the KeyValue store holding OAuth flows and the host
// sessions issued from them using the shared Client. Flows are written for unauthenticated
// requests, so the bucket is bounded to maxBytes and allows per-key TTLs: flows carry the
// short nonce lifetime while ttl, the bucket-wide maximum, covers the longer session lifetime.
// Both are independent of --tokens-ttl. An existing bucket is updated so the limits also apply
// to earlier deployments.
func (c *Client) InitializeSessions(ctx context.Context, ttl time.Duration, maxBytes int64) (KVStore, error) {
	switch {
	case ttl < minKVTTL:
		return nil, fmt.Errorf("invalid TTL for KV bucket %q: %s; must be >= %s", sessionBucket, ttl, minKVTTL)
	case maxBytes <= 0:
		return nil, fmt.Errorf("invalid max bytes for KV bucket %q: %d; must be positive", sessionBucket, maxBytes)
	}

	c.ll.Info(fmt.Sprintf(
		"establishing key/value %s store targeting %s (ttl=%s, max_bytes=%d)",
		sessionBucket,
		c.logHost,
		ttl,
		maxBytes,
	))

	maxValueSize := c.storageArgs.MaxValueSize
	if maxValueSize <= 0 || int64(maxValueSize) > maxBytes {
		maxValueSize = int32(min(maxBytes, math.MaxInt32)) //nolint:gosec // bounded above
	}

	kv, err := c.js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       sessionBucket,
		Replicas:     c.storageArgs.NatsReplicas,
		Storage:      jetstream.MemoryStorage,
		MaxValueSize: maxValueSize,
		MaxBytes:     maxBytes,
		History:      1,
		TTL:          ttl,
		// Enables per-key TTLs, keeping the markers left by expiring keys only briefly.
		LimitMarkerTTL: limitMarkerTTL,
	})
	if err != nil {
		existing, bindErr := c.js.KeyValue(ctx, sessionBucket)
		if bindErr != nil {
			return nil, fmt.Errorf("create KV bucket %q failed: %w; bind failed: %w", sessionBucket, err, bindErr)
		}

		c.ll.Warnf("unable to apply limits to KV bucket %q, binding existing bucket: %s", sessionBucket, err)

		kv = existing
	}

	return &kvStore{
		client: c,
		kv:     kv,
	}, nil
}

// InitializeRoutes starts the NATS stream and consumer used for route management
// using the shared Client.
func (c *Client) InitializeRoutes(ctx context.Context) (PubSub, error) {
	return c.initializePubSub(ctx, routesStream, routesSubject)
}

//

func (c *Client) initializePubSub(ctx context.Context, streamName, subject string) (PubSub, error) {
	c.ll.Info("establishing routes stream targeting " + c.logHost)

	ps := &pubsub{
		client:     c,
		streamName: streamName,
		subject:    subject,
	}

	streamCfg := jetstream.StreamConfig{
		Name:        ps.streamName,
		Replicas:    c.storageArgs.NatsReplicas,
		Subjects:    []string{ps.subject},
		Storage:     jetstream.MemoryStorage,
		MaxMsgs:     1,
		Discard:     jetstream.DiscardOld,
		AllowDirect: true,
	}

	stream, err := c.js.CreateStream(ctx, streamCfg)
	if err != nil {
		if errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
			c.ll.Debugf("stream %s already exists, binding to existing stream", ps.streamName)

			stream, err = c.js.Stream(ctx, ps.streamName)
			if err != nil {
				return nil, fmt.Errorf("failed to bind existing stream %q: %w", ps.streamName, err)
			}
		} else {
			return nil, fmt.Errorf("failed to create stream %q: %w", ps.streamName, err)
		}
	}

	ps.stream = stream

	consumer, err := ps.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       c.storageArgs.Consumer,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    -1,
		DeliverPolicy: jetstream.DeliverLastPolicy,
		AckWait:       15 * time.Second,
		FilterSubject: ps.subject,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating consumer: %w", err)
	}

	ps.consumer = consumer

	return ps, nil
}

func (c *Client) initializeKV(ctx context.Context, bucket string) (KVStore, error) {
	c.ll.Info(fmt.Sprintf(
		"establishing key/value %s store targeting %s",
		bucket,
		c.logHost,
	))

	if c.storageArgs.TokensTTL > 0 && c.storageArgs.TokensTTL < minKVTTL {
		return nil, fmt.Errorf(
			"invalid TTL for KV bucket %q: %s; must be 0 or >= %s",
			bucket,
			c.storageArgs.TokensTTL,
			minKVTTL,
		)
	}

	kv, err := c.js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       bucket,
		Replicas:     c.storageArgs.NatsReplicas,
		Storage:      jetstream.MemoryStorage,
		MaxValueSize: c.storageArgs.MaxValueSize,
		History:      1,
		TTL:          c.storageArgs.TokensTTL,
	})
	if err != nil {
		// Only bind if the bucket actually exists. If binding also fails, return
		// both errors so the original cause is not masked.
		existing, bindErr := c.js.KeyValue(ctx, bucket)
		if bindErr != nil {
			return nil, fmt.Errorf("create KV bucket %q failed: %w; bind failed: %w", bucket, err, bindErr)
		}

		kv = existing
	}

	return &kvStore{
		client: c,
		kv:     kv,
	}, nil
}

//

func buildNatsHost(storageArgs args.Storage) string {
	if strings.HasPrefix(storageArgs.StorageHost, natsHostPrefix) {
		return storageArgs.StorageHost
	}

	if storageArgs.StorageUser != "" && storageArgs.StoragePassword != "" {
		return fmt.Sprintf(
			"%s%s:%s@%s",
			natsHostPrefix,
			storageArgs.StorageUser,
			storageArgs.StoragePassword,
			storageArgs.StorageHost,
		)
	}

	return storageArgs.StorageHost
}

func cleanHostURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "invalid-host"
	}

	return parsedURL.Host
}
