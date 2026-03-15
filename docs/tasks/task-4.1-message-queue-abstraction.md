# Task 4.1: Message Queue Abstraction

| Field | Value |
|-------|-------|
| **ID** | task-4.1 |
| **Phase** | 4 — Message Queue (RabbitMQ) |
| **Priority** | Medium |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

The MCPGuard pipeline runs static analysis directly in a goroutine inside `git_webhook_service.go`. The MCPGuard article specifies RabbitMQ for asynchronous job distribution, enabling horizontal scaling (multiple workers), message persistence (no lost jobs on restart), and decoupled processing.

### Expected Behavior

1. A `MessagePublisher` interface abstracts message publishing, allowing the service layer to publish analysis jobs without knowing the underlying transport.
2. A RabbitMQ implementation connects to a RabbitMQ broker and publishes messages to named queues.
3. A no-op implementation exists for local/mock mode that logs messages without sending them.
4. The implementation is selected based on the `messaging.enabled` config flag.

### Acceptance Criteria

- `MessagePublisher` interface compiles and is usable from the service layer.
- RabbitMQ implementation can connect to a broker and publish JSON messages.
- No-op implementation logs the message and returns nil.
- Config selects the correct implementation at bootstrap.

---

## Technical Specification

### New Dependency

Add to `go.mod`:
```
github.com/rabbitmq/amqp091-go v1.10.0
```

### Create `internal/messaging/publisher.go`

```go
package messaging

import "context"

// MessagePublisher abstracts message queue publishing.
type MessagePublisher interface {
    // Publish sends a message to the specified queue.
    Publish(ctx context.Context, queue string, message []byte) error

    // Close gracefully shuts down the connection.
    Close() error
}
```

### Create `internal/messaging/rabbitmq_publisher.go`

```go
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
```

### Create `internal/messaging/noop_publisher.go`

```go
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
```

### Config Changes

**`config/config.go`:**
```go
type MessagingConfig struct {
    Enabled     bool   `yaml:"enabled"`
    RabbitMQURL string `yaml:"rabbitmq_url"`
}
```

Add `MessagingCfg *MessagingConfig \`yaml:"messaging"\`` to `Config` struct.

**`config/default.yaml`:**
```yaml
messaging:
  enabled: false
  rabbitmq_url: ""
```

**`config/prod.yaml`:**
```yaml
messaging:
  enabled: true
  rabbitmq_url: "amqp://guest:guest@rabbitmq:5672/"
```

### Bootstrap Wiring (`cmd/api/setup/resources.go`)

```go
var publisher messaging.MessagePublisher
if cfg.MessagingCfg != nil && cfg.MessagingCfg.Enabled {
    publisher, err = messaging.NewRabbitMQPublisher(cfg.MessagingCfg.RabbitMQURL)
    if err != nil {
        panic(fmt.Sprintf("failed to connect to RabbitMQ: %v", err))
    }
} else {
    publisher = messaging.NewNoopPublisher()
}
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/messaging/publisher.go` | `MessagePublisher` interface |
| `internal/messaging/rabbitmq_publisher.go` | RabbitMQ implementation |
| `internal/messaging/noop_publisher.go` | No-op/local implementation |

### Files to Modify

| File | Change |
|------|--------|
| `config/config.go` | Add `MessagingConfig` |
| `config/default.yaml` | Add `messaging` section (disabled) |
| `config/prod.yaml` | Add `messaging` section (enabled) |
| `cmd/api/setup/resources.go` | Wire publisher based on config |
| `go.mod` | Add `amqp091-go` dependency |

### Testing

- Unit test `NewNoopPublisher().Publish(...)` returns nil.
- Integration test with a local RabbitMQ instance (or testcontainer) verifying message delivery.
