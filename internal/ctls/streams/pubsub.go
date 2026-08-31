package streams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/nats-io/nats.go/jetstream"
)

type PubSub interface {
	// Publish performs a synchronous publish to a stream targeting the pre-established
	// subject and underlying stream configuration.
	Publish(ctx context.Context, val any) error

	// PublishSingleMsg acts similar to Publish, with the exception it attempt to verify
	// a previously established message does not already exist that is identical to the
	// one provided.
	PublishSingleMsg(ctx context.Context, val any) error

	// Consume will continuously receive messages and handle them with the given function,
	// using the pre-established subject and underlying consumer configuration. The provided
	// jetstream.MessageHandler is not responsible for any message acknowledgement.
	Consume(ctx context.Context, handler jetstream.MessageHandler) error
}

func (p *pubsub) Publish(ctx context.Context, val any) error {
	ctx, endSpan := p.client.ll.StartSpan(ctx, "Publish")
	defer endSpan()

	newData, err := marshalMsg(val)
	if err != nil {
		return err
	}

	_, err = p.client.js.Publish(ctx, p.subject, newData)
	if err != nil {
		err = fmt.Errorf("failed to publish message: %w", err)

		p.client.ll.ErrorCtx(ctx, err.Error())

		return err
	}

	return nil
}

func (p *pubsub) PublishSingleMsg(ctx context.Context, val any) error {
	ctx, endSpan := p.client.ll.StartSpan(ctx, "PublishSingleMsg")
	defer endSpan()

	newData, err := marshalMsg(val)
	if err != nil {
		return err
	}

	// Retrieve the last message from the stream
	lastMsg, err := p.stream.GetLastMsgForSubject(ctx, p.subject)
	if err != nil {
		// Regardless of error we are going to move forward with the process, simply
		// log to assist in debugging if required.
		p.client.ll.DebugCtx(
			ctx,
			fmt.Sprintf("failed to retrieve last message in %s: %s", p.subject, err.Error()),
		)
	}

	// Check for changes if a last message exists
	if lastMsg != nil && reflect.DeepEqual(newData, lastMsg.Data) {
		p.client.ll.DebugCtx(ctx, "no source changes, skipping publish")
		return nil
	}

	// Publish the new message to the stream
	_, err = p.client.js.Publish(ctx, p.subject, newData)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	p.client.ll.DebugCtx(ctx, "published new message in "+p.subject)

	return nil
}

func (p *pubsub) Consume(ctx context.Context, handler jetstream.MessageHandler) error {
	ctx, endSpan := p.client.ll.StartSpan(ctx, "Consume")
	defer endSpan()

	consumeCtx, err := p.consumer.Consume(
		func(msg jetstream.Msg) {
			metadata, _ := msg.Metadata()
			p.client.ll.DebugCtx(
				ctx,
				fmt.Sprintf(
					"consumer received message (stream seq: %d, consumer seq: %d, delivered: %d times)",
					metadata.Sequence.Stream,
					metadata.Sequence.Consumer,
					metadata.NumDelivered,
				),
			)

			handler(msg)

			if err := msg.Ack(); err != nil {
				// Simply log as we can't do anything about this and in most scenario
				// it doesn't really present an issue.
				p.client.ll.ErrorCtx(ctx, "error acknowledging message: "+err.Error())
			}
		},
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			if ctx.Err() != nil {
				return
			}

			p.client.ll.WarnCtx(ctx, "consumer error: "+err.Error())
		}),
	)
	if err != nil {
		err = fmt.Errorf("error starting consumer: %w", err)

		p.client.ll.ErrorCtx(ctx, err.Error())

		return err
	}
	defer consumeCtx.Stop()

	p.client.ll.InfoCtx(ctx, "subscriber active on subject "+p.subject)

	<-ctx.Done()

	p.client.ll.InfoCtx(ctx, "context canceled, stopping subscriber...")

	return nil
}

//

func marshalMsg(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte{}, err
	}

	if len(b) == 0 {
		return []byte{}, errors.New("cannot publish an empty message")
	}

	return b, err
}
