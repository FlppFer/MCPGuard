package messaging

import (
	"context"
	"log/slog"
)

type noopPublisher struct{}

func NewNoopPublisher() MessagePublisher {
	return &noopPublisher{}
}

func (p *noopPublisher) Publish(ctx context.Context, queue string, message []byte) error {
	slog.Debug("NoopPublisher: message not sent (queue disabled)",
		"queue", queue, "message_size", len(message))
	return nil
}

func (p *noopPublisher) Close() error { return nil }
