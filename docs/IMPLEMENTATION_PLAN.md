# MCPGuard — Implementation Plan

> Covers all Go API features that are missing or incomplete, ordered by priority and dependency.
> Each task includes full context for implementation.

---

## Phase 1: Server Hardening & Code Quality

These tasks improve the existing Go API's reliability and code quality before adding new features.

---

### Task 1.1: Graceful Shutdown

**Status:** Not implemented
**Priority:** High
**Estimated effort:** Small

**Problem:**
`cmd/api/setup/routes.go` calls `http.ListenAndServe(":8080", r)` directly inside `InitRoutes()`. If the process receives SIGINT/SIGTERM, in-flight requests and background goroutines (static analysis) are dropped without cleanup.

**Current code (`cmd/api/main.go`):**
```go
func run(ctx context.Context) error {
    cfg, _ := config.LoadConfig()
    resources := setup.Bootstrap(ctx, cfg)
    setup.InitRoutes(resources) // blocks here, no shutdown handling
    return nil
}
```

**Current code (`cmd/api/setup/routes.go`):**
```go
func InitRoutes(resources *Resources) {
    r := chi.NewRouter()
    // ... routes ...
    err := http.ListenAndServe(":8080", r) // no graceful shutdown
    if err != nil { panic(err) }
}
```

**Implementation:**
1. Refactor `InitRoutes` to return `*chi.Mux` instead of blocking.
2. In `main.go`, create an `http.Server` and call `ListenAndServe()` in a goroutine.
3. Listen for `os.Signal` (SIGINT, SIGTERM) via `signal.NotifyContext` or `signal.Notify`.
4. On signal, call `server.Shutdown(ctx)` with a timeout (e.g., 30s).
5. This allows in-flight HTTP requests to complete before exit.

**Files to modify:**
- `cmd/api/main.go` — add signal handling + `http.Server` lifecycle
- `cmd/api/setup/routes.go` — change `InitRoutes` to return `*chi.Mux` (or `http.Handler`)

**Dependencies:** None

---

### Task 1.2: Consistent Structured Logging

**Status:** Partially implemented (mixed `log.Println` and `slog`)
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
`git_webhook_service.go` uses `log.Println` (stdlib), while controllers use `slog`. This makes log output inconsistent and harder to parse.

**Occurrences of `log.Println` / `log.Printf`:**
- `internal/service/git_webhook_service.go` lines 113, 121, 163

**Implementation:**
1. Replace all `log.Println` / `log.Printf` calls with `slog.Error` / `slog.Info` equivalents.
2. Add structured fields (e.g., `"analysis_id"`, `"error"`) for machine-parseable logs.
3. Configure the slog handler level based on `cfg.LogLevel` in `main.go`.

**Files to modify:**
- `internal/service/git_webhook_service.go` — replace `log` calls with `slog`
- `cmd/api/main.go` — configure `slog.SetDefault()` with appropriate handler + level

**Dependencies:** None

---

### Task 1.3: Typed Errors for Service Layer

**Status:** Not implemented (string matching used)
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
`git_webhook_controller.go` uses `strings.Contains(err.Error(), "not complete")` to distinguish error types from `GetAnalysisResult`. This is fragile.

**Current code (`git_webhook_controller.go:144`):**
```go
if strings.Contains(err.Error(), "not complete") {
    c.writeError(w, http.StatusAccepted, "analysis_pending", err.Error())
} else {
    c.writeError(w, http.StatusNotFound, "not_found", err.Error())
}
```

**Implementation:**
1. Create sentinel errors in a new file `internal/service/errors.go`:
   ```go
   var (
       ErrAnalysisNotFound    = errors.New("analysis not found")
       ErrAnalysisNotComplete = errors.New("analysis not complete")
   )
   ```
2. Update `git_webhook_service.go` to return wrapped sentinel errors:
   ```go
   return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
   ```
3. Update controller to use `errors.Is()` instead of string matching.

**Files to create:**
- `internal/service/errors.go`

**Files to modify:**
- `internal/service/git_webhook_service.go` — use sentinel errors
- `internal/controller/git_webhook_controller.go` — use `errors.Is()`

**Dependencies:** None

---

### Task 1.4: Request ID Middleware

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
No request tracing. When multiple analyses run concurrently, it's impossible to correlate log entries to specific HTTP requests.

**Implementation:**
1. Create `internal/middleware/request_id.go`:
   - Generate a UUID (or use `X-Request-ID` header if present).
   - Store in request context.
   - Set `X-Request-ID` response header.
2. Add `slog` attributes for `request_id` in all log calls (or use a middleware that patches the logger in context).
3. Register middleware in `routes.go` at the router level (before auth).

**Files to create:**
- `internal/middleware/request_id.go`

**Files to modify:**
- `cmd/api/setup/routes.go` — register `RequestID` middleware on router

**Dependencies:** None

---

### Task 1.5: Temp Directory Cleanup

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
`utils.DownloadRepo()` clones repos to temp directories. The goroutine in `git_webhook_service.go` does not clean up the cloned directory after analysis completes. Repeated analyses will fill disk.

**Implementation:**
1. Add a `Cleanup()` method to `RepoDownloadResultDTO` (or return the temp dir path).
2. Call `os.RemoveAll(repo.LocalPath)` in a `defer` inside the goroutine after analysis completes (success or failure).
3. Also clean up the zip file after S3 upload succeeds.

**Files to modify:**
- `internal/service/git_webhook_service.go` — add cleanup in goroutine
- `internal/utils/repo_download_utils.go` — (verify temp dir path is accessible for cleanup)

**Dependencies:** None

---

## Phase 2: Docker & Deployment

---

### Task 2.1: Dockerfile (Multi-stage Build)

**Status:** Not implemented
**Priority:** High
**Estimated effort:** Small

**Problem:**
No containerization. The MCPGuard article specifies Docker for isolation and reproducibility.

**Implementation:**
1. Create `Dockerfile` at project root using multi-stage build:
   - **Stage 1 (builder):** `golang:1.25-alpine`, install build deps (gcc for CGO/tree-sitter), `go build -o /app/mcpguard ./cmd/api`
   - **Stage 2 (runtime):** `alpine:3.19`, copy binary, install `git` (needed for clone), expose port 8080.
2. Note: tree-sitter requires CGO. The builder stage needs `CGO_ENABLED=1` and `gcc`/`musl-dev`.

**Files to create:**
- `Dockerfile`

**Dependencies:** Task 1.1 (graceful shutdown — so container stops cleanly)

---

### Task 2.2: Docker Compose (Local Development)

**Status:** Not implemented
**Priority:** High
**Estimated effort:** Small

**Problem:**
No local dev environment definition. Developers must manually set env vars and run the binary.

**Implementation:**
1. Create `docker-compose.yaml` at project root with services:
   - `mcpguard-api` — builds from `Dockerfile`, exposes `:8080`, env vars for auth secrets, `SCOPE=local`
   - `localstack` — (optional, for S3 integration testing) `localstack/localstack`, port 4566
2. Create `.env.example` documenting all required env vars.

**Files to create:**
- `docker-compose.yaml`
- `.env.example`

**Dependencies:** Task 2.1

---

### Task 2.3: GitHub Actions CI Workflow

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
No CI pipeline. The article describes GitHub Actions for automated testing.

**Implementation:**
1. Create `.github/workflows/ci.yaml`:
   - **Trigger:** push to `main`/`develop`, pull requests
   - **Jobs:**
     - `build` — checkout, setup Go 1.25, install gcc (for CGO), `go build ./...`
     - `test` — `go test ./...` (skip CGO-dependent tests on Windows with build tags if needed)
     - `vet` — `go vet ./...`

**Files to create:**
- `.github/workflows/ci.yaml`

**Dependencies:** None

---

## Phase 3: Agentic Analysis Integration (Go API Side)

The MCPGuard article describes a Python agentic worker that performs LLM-based semantic analysis. These tasks implement the **Go API side** of that integration — the interfaces, DTOs, service layer, and endpoints the Python worker will communicate with.

---

### Task 3.1: Agentic Analysis DTOs

**Status:** Not implemented
**Priority:** High
**Estimated effort:** Small

**Problem:**
No data structures for agentic analysis requests/responses.

**Implementation:**
1. Create `internal/model/http/agentic_analysis_dtos.go`:
   ```go
   // AgenticAnalysisRequestDTO — sent TO the Python worker
   type AgenticAnalysisRequestDTO struct {
       AnalysisID string `json:"analysis_id"`
       RepoURL    string `json:"repo_url"`
       Branch     string `json:"branch"`
       Commit     string `json:"commit"`
       SourceKey  string `json:"source_key"` // S3 key for source archive
   }

   // AgenticAnalysisResultDTO — received FROM the Python worker
   type AgenticAnalysisResultDTO struct {
       AnalysisID string                `json:"analysis_id"`
       Findings   []AgenticFindingDTO   `json:"findings"`
       Summary    string                `json:"summary"`
       Timestamp  time.Time             `json:"timestamp"`
   }

   // AgenticFindingDTO — a single finding from semantic analysis
   type AgenticFindingDTO struct {
       Category    string `json:"category"`
       Description string `json:"description"`
       FilePath    string `json:"file_path"`
       Severity    string `json:"severity"`
       Confidence  float64 `json:"confidence"` // 0.0–1.0
       Suggestion  string `json:"suggestion"`
   }
   ```

**Files to create:**
- `internal/model/http/agentic_analysis_dtos.go`

**Dependencies:** None

---

### Task 3.2: Agentic Analysis Service Interface

**Status:** Stub exists (`agentic_analysis_service.go` is empty)
**Priority:** High
**Estimated effort:** Small

**Problem:**
`internal/service/agentic_analysis_service.go` contains only `package service`. No interface or implementation.

**Implementation:**
1. Define the service interface in `agentic_analysis_service.go`:
   ```go
   type AgenticAnalysisService interface {
       // SubmitForAnalysis sends an analysis job to the agentic worker.
       // In the current implementation, this will be a direct HTTP call to the Python API.
       // In the future, this will publish to RabbitMQ.
       SubmitForAnalysis(ctx context.Context, req *http.AgenticAnalysisRequestDTO) error

       // ReceiveResult processes results submitted by the Python worker.
       ReceiveResult(ctx context.Context, result *http.AgenticAnalysisResultDTO) error

       // GetResult retrieves stored agentic analysis results for a given analysis ID.
       GetResult(ctx context.Context, analysisID string) ([]byte, error)
   }
   ```
2. Create `agentic_analysis_service_impl.go` with a basic implementation:
   - `SubmitForAnalysis` — HTTP POST to a configured Python worker URL (from config).
   - `ReceiveResult` — serialize to JSON, upload to S3 as `analysis-results/{id}_agentic.json`, update DB status.
   - `GetResult` — download from S3.
3. Constructor: `NewAgenticAnalysisService(dbRepo, storageRepo, pythonWorkerURL)`.

**Config change needed:**
- Add `AgenticWorkerURL` to `config.Config` / YAML files (e.g., `agentic_worker_url: "http://localhost:5000"`).

**Files to modify:**
- `internal/service/agentic_analysis_service.go` — define interface + implementation
- `config/config.go` — add `AgenticConfig` with `WorkerURL`
- `config/default.yaml` — add agentic config section
- `config/prod.yaml` — add agentic config section

**Dependencies:** Task 3.1

---

### Task 3.3: Agentic Analysis Controller (Implement Endpoints)

**Status:** Stub returns 501
**Priority:** High
**Estimated effort:** Medium

**Problem:**
`agentic_analysis_controller.go` has one endpoint that returns 501. Need real endpoints.

**Implementation:**
1. Inject `AgenticAnalysisService` into the controller constructor.
2. Implement endpoints:
   - `POST /v1/agentic_analysis` — receives `AgenticAnalysisResultDTO` from the Python worker (callback endpoint). Calls `service.ReceiveResult()`.
   - `GET /v1/agentic_analysis/{id}/result` — retrieves stored agentic results. (New endpoint.)
3. Update `AgenticAnalysisControllerInterface` to include new handler methods.
4. Register new routes in `routes.go`.

**Files to modify:**
- `internal/controller/agentic_analysis_controller.go` — full implementation
- `cmd/api/setup/resources.go` — inject `AgenticAnalysisService` into controller
- `cmd/api/setup/routes.go` — register new routes

**Dependencies:** Task 3.2

---

### Task 3.4: Integrate Agentic Submission into Pipeline

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
After static analysis completes, the pipeline stops at `static_done`. It should optionally trigger agentic analysis.

**Current code (`git_webhook_service.go` goroutine, line 129):**
```go
entity.Status = "static_done"
entity.UpdatedAt = time.Now()
uc.dbRepo.Update(context.Background(), entity)
// ← Pipeline ends here. No agentic submission.
```

**Implementation:**
1. Add `agenticService AgenticAnalysisService` to `gitWebhookServiceImpl` struct.
2. After static analysis succeeds (line 129), check if agentic analysis is enabled (config flag).
3. If enabled:
   - Update status to `waiting_agent_analysis`.
   - Build `AgenticAnalysisRequestDTO` with the analysis ID and source S3 key.
   - Call `agenticService.SubmitForAnalysis()`.
   - If submission fails, log error but don't fail the overall analysis.
4. If disabled, keep current behavior (status stays at `static_done` or `completed`).

**Config change:**
- Add `AgenticConfig.Enabled bool` field.

**Files to modify:**
- `internal/service/git_webhook_service.go` — add agentic submission step
- `cmd/api/setup/resources.go` — inject agentic service into webhook service
- `config/config.go` — add `Enabled` flag to agentic config
- `config/default.yaml` — `agentic: enabled: false`
- `config/prod.yaml` — `agentic: enabled: true`

**Dependencies:** Task 3.2, Task 3.3

---

### Task 3.5: Merged Results Endpoint

**Status:** Not implemented
**Priority:** Low
**Estimated effort:** Small

**Problem:**
When both static and agentic analysis are complete, there's no endpoint to get a merged view of all findings.

**Implementation:**
1. Add `GET /v1/analysis/{id}/result/full` endpoint that:
   - Fetches static result JSON from S3 (`{id}_static.json`)
   - Fetches agentic result JSON from S3 (`{id}_agentic.json`)
   - Merges into a combined response
2. Alternatively, modify the existing `GET /v1/analysis/{id}/result` to include both when status is `completed`.
3. Define a `MergedAnalysisResult` DTO that wraps both result types.

**Files to modify:**
- `internal/service/git_webhook_service.go` — new method or update `GetAnalysisResult`
- `internal/controller/git_webhook_controller.go` — new endpoint
- `cmd/api/setup/routes.go` — register route

**Dependencies:** Task 3.3, Task 3.4

---

## Phase 4: Message Queue (RabbitMQ)

The article describes RabbitMQ for async job distribution. These tasks add the Go API producer side.

---

### Task 4.1: Message Queue Abstraction

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Medium

**Problem:**
The pipeline currently uses a bare `go func()` for async analysis. The article requires RabbitMQ.

**Implementation:**
1. Create `internal/messaging/publisher.go`:
   ```go
   type MessagePublisher interface {
       Publish(ctx context.Context, queue string, message []byte) error
       Close() error
   }
   ```
2. Create `internal/messaging/rabbitmq_publisher.go`:
   - Connects to RabbitMQ via `amqp091-go` library.
   - Implements `Publish` — serializes message and sends to named queue.
   - Connection URL from config.
3. Create `internal/messaging/noop_publisher.go`:
   - No-op implementation for local/mock mode (logs messages, doesn't send).

**Config change:**
- Add `MessagingConfig` to `config.Config`:
  ```yaml
  messaging:
    enabled: false      # local
    rabbitmq_url: ""    # prod: "amqp://guest:guest@rabbitmq:5672/"
  ```

**Dependencies needed (go.mod):**
- `github.com/rabbitmq/amqp091-go`

**Files to create:**
- `internal/messaging/publisher.go` — interface
- `internal/messaging/rabbitmq_publisher.go` — RabbitMQ implementation
- `internal/messaging/noop_publisher.go` — mock/local implementation

**Files to modify:**
- `config/config.go` — add `MessagingConfig`
- `config/default.yaml` — add messaging section (disabled)
- `config/prod.yaml` — add messaging section (enabled)
- `go.mod` — add amqp091-go dependency

**Dependencies:** None

---

### Task 4.2: Refactor Pipeline to Use Message Queue

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Medium

**Problem:**
`git_webhook_service.go` runs analysis directly in a goroutine. With RabbitMQ, it should publish a message and let a worker consume it.

**Implementation:**
1. Define analysis job message:
   ```go
   type AnalysisJobMessage struct {
       AnalysisID string   `json:"analysis_id"`
       RepoURL    string   `json:"repo_url"`
       Branch     string   `json:"branch"`
       Commit     string   `json:"commit"`
       SourceKey  string   `json:"source_key"` // S3 key for source archive
   }
   ```
2. Two modes in `RequestAnalysis()`:
   - **Queue enabled:** After uploading source, publish `AnalysisJobMessage` to `static_analysis` queue. Return immediately.
   - **Queue disabled (current):** Run analysis in goroutine (existing behavior).
3. Create `internal/worker/static_analysis_worker.go`:
   - Subscribes to `static_analysis` queue.
   - On message: downloads source from S3, parses files, runs analysis, uploads results.
   - This worker can run in the same binary (started in `main.go`) or as a separate process.
4. Add a `--worker` CLI flag or `MODE=worker` env var to start the binary in worker mode instead of API mode.

**Files to create:**
- `internal/messaging/messages.go` — message type definitions
- `internal/worker/static_analysis_worker.go` — consumer worker

**Files to modify:**
- `internal/service/git_webhook_service.go` — conditional publish vs goroutine
- `cmd/api/main.go` — add worker mode startup
- `cmd/api/setup/resources.go` — wire `MessagePublisher`

**Dependencies:** Task 4.1

---

### Task 4.3: Add RabbitMQ to Docker Compose

**Status:** Not implemented
**Priority:** Low
**Estimated effort:** Small

**Implementation:**
1. Add `rabbitmq` service to `docker-compose.yaml`:
   ```yaml
   rabbitmq:
     image: rabbitmq:3-management-alpine
     ports:
       - "5672:5672"
       - "15672:15672"   # management UI
     environment:
       RABBITMQ_DEFAULT_USER: guest
       RABBITMQ_DEFAULT_PASS: guest
   ```
2. Update `mcpguard-api` service to depend on `rabbitmq` and set `RABBITMQ_URL`.

**Files to modify:**
- `docker-compose.yaml`

**Dependencies:** Task 2.2, Task 4.1

---

## Phase 5: Observability

---

### Task 5.1: Prometheus Metrics Endpoint

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Medium

**Problem:**
The article describes Prometheus + Grafana for observability. No `/metrics` endpoint exists.

**Implementation:**
1. Add `github.com/prometheus/client_golang` dependency.
2. Create `internal/middleware/metrics.go`:
   - Register default metrics: `http_requests_total`, `http_request_duration_seconds`, `http_response_size_bytes`.
   - Middleware wraps `http.Handler`, records labels: `method`, `path`, `status`.
3. Register custom metrics:
   - `mcpguard_analyses_total` (counter, labels: `status`, `trigger_type`)
   - `mcpguard_analysis_duration_seconds` (histogram)
   - `mcpguard_findings_total` (counter, labels: `severity`, `rule_id`)
4. Expose `/metrics` endpoint in `routes.go` using `promhttp.Handler()`.
5. Instrument service layer to increment counters.

**Files to create:**
- `internal/middleware/metrics.go` — HTTP metrics middleware + custom metrics

**Files to modify:**
- `cmd/api/setup/routes.go` — register `/metrics` endpoint + middleware
- `internal/service/git_webhook_service.go` — increment analysis counters
- `go.mod` — add prometheus client dependency

**Dependencies:** None

---

### Task 5.2: Grafana Dashboard Definition

**Status:** Not implemented
**Priority:** Low
**Estimated effort:** Small

**Implementation:**
1. Create `deploy/grafana/dashboards/mcpguard.json` — Grafana dashboard JSON:
   - Panels: analyses/hour, findings by severity, findings by rule category, analysis duration histogram, error rate.
2. Create `deploy/grafana/provisioning/datasources.yaml` — auto-provision Prometheus datasource.
3. Create `deploy/grafana/provisioning/dashboards.yaml` — auto-provision dashboard.
4. Add Grafana + Prometheus to `docker-compose.yaml`:
   ```yaml
   prometheus:
     image: prom/prometheus:latest
     volumes:
       - ./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
     ports:
       - "9090:9090"

   grafana:
     image: grafana/grafana:latest
     volumes:
       - ./deploy/grafana/provisioning:/etc/grafana/provisioning
       - ./deploy/grafana/dashboards:/var/lib/grafana/dashboards
     ports:
       - "3000:3000"
   ```
5. Create `deploy/prometheus/prometheus.yml` — scrape config targeting `mcpguard-api:8080/metrics`.

**Files to create:**
- `deploy/prometheus/prometheus.yml`
- `deploy/grafana/dashboards/mcpguard.json`
- `deploy/grafana/provisioning/datasources.yaml`
- `deploy/grafana/provisioning/dashboards.yaml`

**Files to modify:**
- `docker-compose.yaml` — add prometheus + grafana services

**Dependencies:** Task 5.1, Task 2.2

---

## Phase 6: GitHub Actions PR Integration

---

### Task 6.1: PR Comment Service

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Medium

**Problem:**
The article describes auto-commenting analysis findings on Pull Requests. No such functionality exists.

**Implementation:**
1. Create `internal/service/github_integration/pr_comment_service.go`:
   ```go
   type PRCommentService interface {
       PostFindings(ctx context.Context, repoFullName string, prNumber int, findings []model.Finding) error
   }
   ```
2. Implementation uses GitHub REST API (`POST /repos/{owner}/{repo}/issues/{pr_number}/comments`).
3. Format findings as a Markdown table/summary for the PR comment.
4. Auth: GitHub App token or Personal Access Token (from env var `GITHUB_TOKEN`).
5. Add `github_integration` config section with `enabled`, `token_env_var`.

**Files to create:**
- `internal/service/github_integration/pr_comment_service.go`
- `internal/service/github_integration/markdown_formatter.go` — formats findings as Markdown

**Files to modify:**
- `config/config.go` — add `GitHubIntegrationConfig`
- `config/default.yaml` / `config/prod.yaml` — add config section

**Dependencies:** None

---

### Task 6.2: GitHub Actions Workflow for MCPGuard Analysis

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
No reusable GitHub Actions workflow that external repos can use to trigger MCPGuard analysis.

**Implementation:**
1. Create `.github/workflows/mcpguard-analysis.yaml` — a reusable workflow:
   - Triggered by `workflow_call` (reusable) or `repository_dispatch`.
   - Steps: call MCPGuard API → poll status → fetch results → post PR comment (using GitHub API).
2. Alternatively, create a shell script `scripts/mcpguard-analyze.sh` that repos can call from their own workflows.

**Files to create:**
- `.github/workflows/mcpguard-analysis.yaml`
- (optional) `scripts/mcpguard-analyze.sh`

**Dependencies:** Task 6.1 (for PR commenting from the API side)

---

### Task 6.3: Extract PR Number from Webhook Payload

**Status:** Not implemented
**Priority:** Medium
**Estimated effort:** Small

**Problem:**
The current `GitHubPushPayload` only handles push events. For PR commenting, the API needs to handle `pull_request` events too.

**Implementation:**
1. Add `GitHubPullRequestPayload` DTO in `internal/model/http/git_webhook_request.go`:
   ```go
   type GitHubPullRequestPayload struct {
       Action      string `json:"action"` // "opened", "synchronize", etc.
       Number      int    `json:"number"` // PR number
       PullRequest struct {
           Head struct {
               Ref string `json:"ref"`
               SHA string `json:"sha"`
           } `json:"head"`
       } `json:"pull_request"`
       Repository struct {
           CloneURL string `json:"clone_url"`
           FullName string `json:"full_name"`
       } `json:"repository"`
   }
   ```
2. Update `HandleGitHubWebhook()` to check `X-GitHub-Event` header:
   - `push` → existing flow
   - `pull_request` → new flow that stores PR number for later comment posting
3. Store `pr_number` and `repo_full_name` on `AnalysisEntity` (new columns).

**Files to modify:**
- `internal/model/http/git_webhook_request.go` — add PR payload DTO
- `internal/model/repositories/analysis_entity.go` — add `PRNumber`, `RepoFullName` columns
- `internal/controller/git_webhook_controller.go` — handle PR events
- `internal/service/git_webhook_service.go` — pass PR metadata through pipeline

**Dependencies:** Task 6.1

---

## Phase 7: Multi-Language Rule Expansion

---

### Task 7.1: JavaScript/TypeScript Rule Foundation

**Status:** Not implemented
**Priority:** Low
**Estimated effort:** Medium

**Problem:**
Only Python has rules. The registry supports multi-language, but no JS/TS parser or rules exist.

**Implementation:**
1. Add tree-sitter JavaScript grammar dependency.
2. Create `internal/service/static_analysis/languages/javascript/parser.go`:
   - `JavaScriptAST` struct (mirrors `PythonAST`).
   - Parse `.js`/`.ts` files.
3. Create initial rule files (start with the highest-impact categories):
   - `javascript_rule_command_injection.go` — `child_process.exec`, `eval()`
   - `javascript_rule_file_operations.go` — `fs.readFile`, `fs.writeFile`, `fs.unlink`
4. Register rules with `LanguageJavaScript = "javascript"` in `rule_registry.go`.
5. Update `utils/file_utils.go` to map `.js` / `.ts` extensions to `"javascript"`.

**Files to create:**
- `internal/service/static_analysis/languages/javascript/parser.go`
- `internal/service/static_analysis/languages/javascript/rules/javascript_rule_command_injection.go`
- `internal/service/static_analysis/languages/javascript/rules/javascript_rule_file_operations.go`
- Corresponding `_test.go` files
- `resources/test/` — JS test fixtures

**Files to modify:**
- `internal/service/static_analysis/rule_registry.go` — add `LanguageJavaScript`
- `internal/utils/file_utils.go` — add `.js`, `.ts` extension mapping
- `internal/service/static_analysis/engine.go` — ensure JS parser is invoked for JS files

**Dependencies:** None (but tree-sitter CGO must work in build env)

---

## Summary — Dependency Graph

```
Phase 1 (Hardening)          Phase 2 (Docker)           Phase 3 (Agentic)
├─ 1.1 Graceful Shutdown ──▶ 2.1 Dockerfile             3.1 DTOs
├─ 1.2 Structured Logging    2.2 Docker Compose ◀── 2.1  3.2 Service ◀── 3.1
├─ 1.3 Typed Errors          2.3 CI Workflow             3.3 Controller ◀── 3.2
├─ 1.4 Request ID                                        3.4 Pipeline Integration ◀── 3.2
└─ 1.5 Temp Cleanup                                      3.5 Merged Results ◀── 3.4

Phase 4 (RabbitMQ)           Phase 5 (Observability)    Phase 6 (GitHub PR)
├─ 4.1 Queue Abstraction     5.1 Prometheus Endpoint     6.1 PR Comment Service
├─ 4.2 Pipeline Refactor     5.2 Grafana Dashboard       6.2 Actions Workflow ◀── 6.1
│      ◀── 4.1                    ◀── 5.1, 2.2           6.3 PR Payload ◀── 6.1
└─ 4.3 Docker RabbitMQ
       ◀── 4.1, 2.2

Phase 7 (Multi-lang)
└─ 7.1 JS/TS Rules
```

---

## Recommended Implementation Order

| Order | Task | Rationale |
|-------|------|-----------|
| 1 | 1.1 Graceful Shutdown | Foundation for reliable server lifecycle |
| 2 | 1.2 Structured Logging | Needed before adding more complex features |
| 3 | 1.3 Typed Errors | Clean error handling before more service methods |
| 4 | 1.4 Request ID | Tracing needed before scaling |
| 5 | 1.5 Temp Cleanup | Prevents disk exhaustion in current usage |
| 6 | 2.1 Dockerfile | Required for any deployment |
| 7 | 2.2 Docker Compose | Local dev convenience |
| 8 | 2.3 CI Workflow | Automate build/test |
| 9 | 3.1–3.4 Agentic Analysis | Core missing feature from the article |
| 10 | 5.1 Prometheus Metrics | Observability before production |
| 11 | 4.1–4.2 RabbitMQ | Scalability (can defer if single-instance is fine) |
| 12 | 6.1–6.3 GitHub PR Integration | CI/CD feedback loop |
| 13 | 5.2 Grafana Dashboard | Nice-to-have after metrics exist |
| 14 | 4.3 Docker RabbitMQ | After queue code is ready |
| 15 | 7.1 JS/TS Rules | Extend language coverage |
| 16 | 3.5 Merged Results | After agentic pipeline works end-to-end |
