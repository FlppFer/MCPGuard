# Task 3.6: Connect to Real Agentic Analysis Service

| Field | Value |
|-------|-------|
| **ID** | task-3.6 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | High |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | task-3.4 (Integrate Agentic Submission into Pipeline) |

---

## Functional Specification

### Problem Statement

The agentic analysis pipeline currently uses a mock implementation (`agentic_analysis_service_mock.go`) that generates fake findings locally. When the real Python agentic worker is deployed, the Go API must connect to it via HTTP, send analysis jobs, and receive results through the callback endpoint.

### Current State

- `AgenticAnalysisService` interface is defined with `SubmitForAnalysis`, `ReceiveResult`, and `GetResult`.
- Two implementations exist:
  - **Real** (`agentic_analysis_service.go`): sends HTTP POST to `worker_url/analyze`, but the Python worker doesn't exist yet.
  - **Mock** (`agentic_analysis_service_mock.go`): generates fake findings and self-persists immediately.
- Config selects implementation via `agentic.mock: true/false`.
- The callback endpoint `POST /v1/agentic_analysis` is already wired and functional.

### Expected Behavior

1. The real Python agentic worker is deployed and accessible at the configured `worker_url`.
2. `SubmitForAnalysis` sends the analysis request to the worker, which processes it asynchronously.
3. The worker calls back `POST /v1/agentic_analysis` with `AgenticAnalysisResultDTO` when done.
4. `ReceiveResult` persists findings to S3 and updates the analysis status to `completed`.
5. Error handling: timeouts, retries, and worker unavailability are handled gracefully.

### Acceptance Criteria

- With `agentic.mock: false` and a running Python worker, the full pipeline completes end-to-end.
- `SubmitForAnalysis` includes proper timeout handling and retry logic.
- Authentication between Go API and Python worker is implemented (shared secret or API key).
- Worker health check is performed before submitting jobs.
- Failed submissions fall back to `static_analysis_done` status (existing behavior).
- Integration test validates the full round-trip with a real or test worker.

---

## Technical Specification

### Changes Required

#### 1. Add authentication to worker communication

**`internal/service/agentic_analysis_service.go`:**
- Add `Authorization` header to HTTP requests sent to the worker.
- Worker secret should come from config or environment variable.

**`config/config.go`:**
```go
AgenticConfig struct {
    Enabled      bool   `yaml:"enabled"`
    Mock         bool   `yaml:"mock"`
    WorkerURL    string `yaml:"worker_url"`
    WorkerSecret string `yaml:"worker_secret"` // Shared secret for worker auth
}
```

#### 2. Add retry logic to SubmitForAnalysis

- Retry up to 3 times with exponential backoff on transient failures (5xx, timeouts).
- Log each retry attempt with structured fields.

#### 3. Add worker health check

- Before submitting, optionally ping `GET {worker_url}/health`.
- If health check fails, skip agentic analysis and log a warning.

#### 4. Add callback authentication

- The Python worker should include an auth header when calling back `POST /v1/agentic_analysis`.
- Validate the header in the controller or via a dedicated middleware for the callback route.

#### 5. Update Docker Compose for worker

**`docker-compose.yaml`:**
```yaml
  agentic-worker:
    image: mcpguard-agentic-worker:latest
    environment:
      - MCPGUARD_CALLBACK_URL=http://mcpguard-api:8080/v1/agentic_analysis
      - MCPGUARD_WORKER_SECRET=${AGENTIC_WORKER_SECRET:-dev-worker-secret}
    depends_on:
      - mcpguard-api
    profiles:
      - agentic
```

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/agentic_analysis_service.go` | Add auth headers, retry logic, health check |
| `config/config.go` | Add `WorkerSecret` field |
| `config/default.yaml` | Add `worker_secret` placeholder |
| `config/prod.yaml` | Add `worker_secret` env var reference |
| `docker-compose.yaml` | Add agentic-worker service |
| `internal/controller/agentic_analysis_controller.go` | Add callback auth validation |

### Testing

- Integration test with a test HTTP server simulating the Python worker.
- Verify retry logic with a flaky mock server (fail first N requests, then succeed).
- Verify auth header is present and validated on both sides.
- Verify graceful degradation when worker is unavailable.
