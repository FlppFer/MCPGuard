# Task 4.2: Refactor Pipeline to Use Message Queue

| Field | Value |
|-------|-------|
| **ID** | task-4.2 |
| **Phase** | 4 — Message Queue (RabbitMQ) |
| **Priority** | Medium |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | task-4.1 (Message Queue Abstraction) |

---

## Functional Specification

### Problem Statement

`git_webhook_service.go` runs static analysis in a bare `go func()`. This has no retry, no persistence, no horizontal scaling, and ties analysis to the API process lifecycle. With RabbitMQ, the API should publish a job message and let independent workers consume it.

### Expected Behavior

1. **Queue enabled:** After uploading the source archive, the API publishes an `AnalysisJobMessage` to the `static_analysis` queue and returns immediately. A separate worker process consumes the message and runs the analysis.
2. **Queue disabled (current behavior):** Analysis runs in a goroutine (preserving backward compatibility for local development).
3. The worker can run in the same binary (via a `--worker` flag or `MODE=worker` env var) or as a separate process.

### Acceptance Criteria

- With `messaging.enabled: false`, the existing goroutine-based analysis still works.
- With `messaging.enabled: true`, a message is published to RabbitMQ instead of running in a goroutine.
- A worker binary/mode can consume messages from the queue and run analysis.
- Failed analysis messages are nack'd and re-queued (at-least-once delivery).

---

## Technical Specification

### Message Definition

Create `internal/messaging/messages.go`:

```go
package messaging

// Queue name constants
const (
    QueueStaticAnalysis  = "mcpguard.static_analysis"
    QueueAgenticAnalysis = "mcpguard.agentic_analysis"
)

// AnalysisJobMessage is published to the static analysis queue.
type AnalysisJobMessage struct {
    AnalysisID string `json:"analysis_id"`
    RepoURL    string `json:"repo_url"`
    Branch     string `json:"branch"`
    Commit     string `json:"commit"`
    SourceKey  string `json:"source_key"` // S3 key for source archive
}
```

### Pipeline Refactor (`git_webhook_service.go`)

Replace the goroutine block with conditional logic:

```go
if uc.publisher != nil && uc.queueEnabled {
    // Publish to queue — worker will handle analysis
    jobMsg := &messaging.AnalysisJobMessage{
        AnalysisID: analysisID,
        RepoURL:    repoURL,
        Branch:     branch,
        Commit:     commit,
        SourceKey:  fmt.Sprintf("%s.zip", analysisID),
    }
    msgBytes, _ := json.Marshal(jobMsg)
    if err := uc.publisher.Publish(ctx, messaging.QueueStaticAnalysis, msgBytes); err != nil {
        slog.Error("Failed to publish analysis job", "analysis_id", analysisID, "error", err)
        entity.Status = "failed"
        entity.ErrorMessage = fmt.Sprintf("queue publish failed: %v", err)
        uc.dbRepo.Update(ctx, entity)
        return nil, err
    }
    entity.Status = "queued"
    uc.dbRepo.Update(ctx, entity)
} else {
    // Existing goroutine-based analysis (local mode)
    go func() { /* ... existing code ... */ }()
}
```

### Worker Implementation

Create `internal/worker/static_analysis_worker.go`:

```go
package worker

type StaticAnalysisWorker struct {
    consumer    *amqp.Channel
    dbRepo      db.DatabaseClient
    storageRepo obj_storage.StorageRepository
    analyzer    static_analysis.Service
}

func (w *StaticAnalysisWorker) Start(ctx context.Context) error {
    msgs, err := w.consumer.Consume(messaging.QueueStaticAnalysis, "", false, false, false, false, nil)
    // ...
    for msg := range msgs {
        var job messaging.AnalysisJobMessage
        json.Unmarshal(msg.Body, &job)

        // Download source from S3, parse files, run analysis, upload results
        // On success: msg.Ack(false)
        // On failure: msg.Nack(false, true) // requeue
    }
}
```

### Binary Mode Selection

In `cmd/api/main.go`, check `MODE` env var:

```go
mode := os.Getenv("MODE")
switch mode {
case "worker":
    // Start worker mode (consume from queue)
    return runWorker(ctx, cfg)
default:
    // Start API mode (serve HTTP)
    return runAPI(ctx, cfg)
}
```

### New Status Value

Add `StatusQueued` to the status enum in `analysis_entity.go`:

```go
const StatusQueued AnalysisStatus = // after StatusCreated
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/messaging/messages.go` | Message types and queue constants |
| `internal/worker/static_analysis_worker.go` | Queue consumer / worker |

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/git_webhook_service.go` | Conditional publish vs goroutine |
| `internal/model/repositories/analysis_entity.go` | Add `StatusQueued` |
| `cmd/api/main.go` | Add `MODE` env var check, `runWorker` function |
| `cmd/api/setup/resources.go` | Wire `MessagePublisher` into webhook service |

### Testing

- With queue disabled: existing test suite passes unchanged.
- With queue enabled + test RabbitMQ: verify message appears on queue.
- Worker integration test: publish message → worker consumes → results uploaded to mock S3.
