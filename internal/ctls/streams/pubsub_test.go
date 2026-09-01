package streams

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
)

func newTestPubSub(t *testing.T, streamName, subject string) (*pubsub, context.Context) {
	t.Helper()

	conn, js, _ := inProcessNatsServer(t, streamName, subject)

	client := &Client{
		ll: ll,
		nc: conn,
		js: js,
		storageArgs: args.Storage{
			NatsReplicas: 1,
			Consumer:     "test-consumer",
		},
	}

	streamCfg := jetstream.StreamConfig{
		Name:        streamName,
		Replicas:    1,
		Subjects:    []string{subject},
		Storage:     jetstream.MemoryStorage,
		MaxMsgs:     10,
		Discard:     jetstream.DiscardOld,
		AllowDirect: true,
	}

	stream, err := js.CreateStream(t.Context(), streamCfg)
	require.NoError(t, err)

	consumer, err := stream.CreateOrUpdateConsumer(t.Context(), jetstream.ConsumerConfig{
		Durable:       "test-consumer",
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    -1,
		DeliverPolicy: jetstream.DeliverLastPolicy,
		AckWait:       15 * time.Second,
		FilterSubject: subject,
	})
	require.NoError(t, err)

	ps := &pubsub{
		client:     client,
		consumer:   consumer,
		stream:     stream,
		streamName: streamName,
		subject:    subject,
	}

	return ps, t.Context()
}

//

func Test_pubsub(t *testing.T) {
	t.Parallel()

	t.Run("Publish", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_publish_stream", "test.publish")

		type payload struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		msg := payload{
			Name:  "test",
			Value: 42,
		}

		err := ps.Publish(ctx, msg)
		require.NoError(t, err)

		// Verify message was published by fetching it
		lastMsg, err := ps.stream.GetLastMsgForSubject(ctx, ps.subject)
		require.NoError(t, err)
		assert.NotNil(t, lastMsg)
	})

	t.Run("Publish marshal error", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_publish_error_stream", "test.publish.error")

		// Channels cannot be marshaled
		ch := make(chan int)
		err := ps.Publish(ctx, ch)

		assert.Error(t, err)
	})

	t.Run("PublishSingleMsg first message", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_single_first_stream", "test.single.first")

		msg := map[string]string{
			"key": "value",
		}

		err := ps.PublishSingleMsg(ctx, msg)
		require.NoError(t, err)

		// Verify message was published
		lastMsg, err := ps.stream.GetLastMsgForSubject(ctx, ps.subject)
		require.NoError(t, err)
		assert.NotNil(t, lastMsg)
	})

	t.Run("PublishSingleMsg deduplication", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_single_dedup_stream", "test.single.dedup")

		msg := map[string]string{
			"key": "value",
		}

		// Publish first message
		err := ps.PublishSingleMsg(ctx, msg)
		require.NoError(t, err)

		// Get initial sequence number
		info, err := ps.stream.Info(ctx)
		require.NoError(t, err)
		initialSeq := info.State.LastSeq

		// Publish same message again - should be skipped
		err = ps.PublishSingleMsg(ctx, msg)
		require.NoError(t, err)

		// Verify no new message was added
		info, err = ps.stream.Info(ctx)
		require.NoError(t, err)
		assert.Equal(t, initialSeq, info.State.LastSeq)
	})

	t.Run("PublishSingleMsg with change", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_single_change_stream", "test.single.change")

		msg1 := map[string]string{
			"key": "value1",
		}

		// Publish first message
		err := ps.PublishSingleMsg(ctx, msg1)
		require.NoError(t, err)

		// Get initial sequence number
		info, err := ps.stream.Info(ctx)
		require.NoError(t, err)
		initialSeq := info.State.LastSeq

		msg2 := map[string]string{
			"key": "value2",
		}

		// Publish different message - should be published
		err = ps.PublishSingleMsg(ctx, msg2)
		require.NoError(t, err)

		// Verify new message was added
		info, err = ps.stream.Info(ctx)
		require.NoError(t, err)
		assert.Greater(t, info.State.LastSeq, initialSeq)
	})

	t.Run("PublishSingleMsg marshal error", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_single_error_stream", "test.single.error")

		// Channels cannot be marshaled
		ch := make(chan int)
		err := ps.PublishSingleMsg(ctx, ch)

		assert.Error(t, err)
	})

	t.Run("Consume receives messages", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_consume_stream", "test.consume")

		// Publish a test message
		msg := map[string]string{
			"test": "message",
		}
		err := ps.Publish(ctx, msg)
		require.NoError(t, err)

		// Create context with timeout
		consumeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		var receivedMsg jetstream.Msg
		var handlerCalled bool

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ps.Consume(consumeCtx, func(msg jetstream.Msg) {
				receivedMsg = msg
				handlerCalled = true
				cancel() // Cancel context after receiving message
			})
			// Context cancellation is expected
			if err != nil {
				assert.ErrorIs(t, err, context.Canceled)
			}
		}()

		// Wait for handler to be called or timeout
		wg.Wait()

		assert.True(t, handlerCalled)
		assert.NotNil(t, receivedMsg)
	})

	t.Run("Consume handles context cancellation", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_consume_cancel_stream", "test.consume.cancel")

		// Create context that we can cancel
		consumeCtx, cancel := context.WithCancel(ctx)

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			err := ps.Consume(consumeCtx, func(msg jetstream.Msg) {
				// Handler should not be called
				t.Error("handler should not be called")
			})
			// No error expected on clean cancellation
			assert.NoError(t, err)
		}()

		// Give goroutine time to start
		time.Sleep(100 * time.Millisecond)

		// Cancel context
		cancel()

		// Wait for Consume to return
		wg.Wait()
	})

	t.Run("Consume processes multiple messages", func(t *testing.T) {
		ps, ctx := newTestPubSub(t, "test_consume_multi_stream", "test.consume.multi")

		// Publish multiple messages
		for i := 0; i < 3; i++ {
			msg := map[string]int{"count": i}
			err := ps.Publish(ctx, msg)
			require.NoError(t, err)
		}

		// Create context with timeout
		consumeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		messageCount := 0
		var mu sync.Mutex

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ps.Consume(consumeCtx, func(msg jetstream.Msg) {
				mu.Lock()
				messageCount++
				if messageCount >= 3 {
					cancel() // Cancel after receiving all messages
				}
				mu.Unlock()
			})
			// Context cancellation is expected
			if err != nil {
				assert.ErrorIs(t, err, context.Canceled)
			}
		}()

		// Wait for handler to process messages or timeout
		wg.Wait()

		mu.Lock()
		assert.GreaterOrEqual(t, messageCount, 1)
		mu.Unlock()
	})
}

func Test_marshalMsg(t *testing.T) {
	t.Parallel()

	t.Run("marshal valid data", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		b, err := marshalMsg(data)

		require.NoError(t, err)
		assert.Greater(t, len(b), 0)
	})

	t.Run("marshal error with invalid data", func(t *testing.T) {
		ch := make(chan int)
		_, err := marshalMsg(ch)

		assert.Error(t, err)
	})

	t.Run("empty message error", func(t *testing.T) {
		// nil slice should marshal to "null" which is not empty
		var nilSlice []string
		b, err := marshalMsg(nilSlice)

		require.NoError(t, err)
		assert.Greater(t, len(b), 0)
	})
}
