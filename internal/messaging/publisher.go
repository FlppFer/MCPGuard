package messaging

import "context"

// MessagePublisher abstracts message queue publishing.
type MessagePublisher interface {
	// Publish sends a message to the specified queue.
	Publish(ctx context.Context, queue string, message []byte) error

	// Close gracefully shuts down the connection.
	Close() error
}
