package messaging

import (
	"context"
	"fmt"
	"log/slog"

	amqp "github.com/rabbitmq/amqp091-go"
)

type rabbitMQPublisher struct {
	conn    *amqp.Connection
	channel *amqp.Channel
}

func NewRabbitMQPublisher(url string) (MessagePublisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ at %s: %w", url, err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}
	slog.Info("Connected to RabbitMQ", "url", url)
	return &rabbitMQPublisher{conn: conn, channel: ch}, nil
}

func (p *rabbitMQPublisher) Publish(ctx context.Context, queue string, message []byte) error {
	// Declare queue (idempotent)
	_, err := p.channel.QueueDeclare(queue, true, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("failed to declare queue %s: %w", queue, err)
	}

	return p.channel.PublishWithContext(ctx, "", queue, false, false, amqp.Publishing{
		ContentType:  "application/json",
		Body:         message,
		DeliveryMode: amqp.Persistent,
	})
}

func (p *rabbitMQPublisher) Close() error {
	if err := p.channel.Close(); err != nil {
		return err
	}
	return p.conn.Close()
}
