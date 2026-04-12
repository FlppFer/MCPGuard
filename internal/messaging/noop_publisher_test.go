package messaging

import (
	"context"
	"testing"
)

func TestNoopPublisher_Publish(t *testing.T) {
	publisher := NewNoopPublisher()

	err := publisher.Publish(context.Background(), "test-queue", []byte(`{"test": true}`))
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestNoopPublisher_Close(t *testing.T) {
	publisher := NewNoopPublisher()

	err := publisher.Close()
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}
