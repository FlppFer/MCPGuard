# Task 4.3: Add RabbitMQ to Docker Compose

| Field | Value |
|-------|-------|
| **ID** | task-4.3 |
| **Phase** | 4 — Message Queue (RabbitMQ) |
| **Priority** | Low |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-2.2 (Docker Compose), task-4.1 (Queue Abstraction) |

---

## Functional Specification

### Problem Statement

Once the message queue abstraction and pipeline refactor are in place, developers need a RabbitMQ instance for local testing. It should be easy to spin up alongside the API.

### Expected Behavior

1. `docker compose --profile queue up` starts RabbitMQ alongside the MCPGuard API.
2. RabbitMQ management UI is accessible at `http://localhost:15672`.
3. A separate `mcpguard-worker` service consumes from the queue.

### Acceptance Criteria

- RabbitMQ starts and is reachable from the API container.
- Management UI is accessible.
- Worker service starts and connects to the queue.

---

## Technical Specification

### Add to `docker-compose.yaml`

```yaml
  rabbitmq:
    image: rabbitmq:3-management-alpine
    ports:
      - "5672:5672"     # AMQP
      - "15672:15672"   # Management UI
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    profiles:
      - queue

  mcpguard-worker:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - MODE=worker
      - SCOPE=local
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
      - GITHUB_WEBHOOK_SECRET=${GITHUB_WEBHOOK_SECRET:-default-webhook-secret}
      - MCPGUARD_API_KEYS=${MCPGUARD_API_KEYS:-dev-client:dev-key}
    depends_on:
      rabbitmq:
        condition: service_healthy
    profiles:
      - queue
```

Update `mcpguard-api` service to optionally depend on RabbitMQ when queue profile is active and set `RABBITMQ_URL` env var.

### Files to Modify

| File | Change |
|------|--------|
| `docker-compose.yaml` | Add `rabbitmq` and `mcpguard-worker` services under `queue` profile |

### Testing

1. `docker compose --profile queue up` — verify all three services start.
2. Visit `http://localhost:15672` (guest/guest) — verify RabbitMQ management UI.
3. Trigger an analysis via API — verify message appears in queue and worker processes it.
