# MCPGuard — Technical Specifications

> Version: 1.0 — Aligned with codebase as of March 2026

---

## 1. System Overview

MCPGuard is a Go-based REST API that performs automated static security analysis on MCP (Model Context Protocol) server implementations. It receives analysis requests, clones target repositories, parses source code into ASTs, applies 31 security rules based on the MCPLib attack taxonomy, and persists structured findings.

**Module path:** `github.com/FlppFer/MCPGuard`

---

## 2. Technology Stack

| Layer | Technology | Version / Notes |
|-------|-----------|----------------|
| Language | Go | 1.25+ |
| HTTP Router | go-chi/chi | v5 |
| AST Parsing | go-tree-sitter | Python grammar (CGO dependency) |
| ORM / Database | GORM + SQLite | In-memory mock or file-based |
| Object Storage | AWS SDK v2 (S3) | LocalStack for local dev; local filesystem mock |
| UUID | google/uuid | v4 UUIDs for analysis IDs |
| Configuration | YAML | Embedded via `go:embed`, selected by `SCOPE` env var |
| Testing | go test | + LocalStack for S3 integration tests |

---

## 3. Project Structure

```
cmd/api/
  main.go                        → Application entrypoint (port :8080)
  setup/
    resources.go                 → Dependency injection / bootstrap
    routes.go                    → Route registration (chi)

config/
  config.go                      → Config structs + go:embed
  config_loader.go               → YAML loader (scope-based selection)
  default.yaml                   → Local/dev config (mock: true)
  prod.yaml                      → Production config (S3, file SQLite)

internal/
  controller/
    git_webhook_controller.go    → HTTP handlers for webhook + analysis endpoints
    agentic_analysis_controller.go → Stub (not implemented)

  middleware/auth/
    auth.go                      → Auth middleware (generic + webhook-specific)
    types.go                     → Authenticator & WebhookSignatureValidator interfaces

  model/
    http/
      git_webhook_request.go     → WebHookRequestDTO, GitHubPushPayload
      git_webhook_response.go    → WebHookResponseDTO, ErrorResponseDTO
    services/
      git_webhook_analysis_result.go → GitWebhookAnalysisResultDTO, AnalysisStatusDTO
      sourcefile.go              → SourceFileDTO (path, language, content, AST, metadata)
      repo_download_result.go    → RepoDownloadResultDTO
    repositories/
      analysis_entity.go         → AnalysisEntity (GORM model), AnalysisStatus enum

  repositories/
    db/
      analysis_db_client.go      → DatabaseClient interface + factory (mock / file SQLite)
    obj_storage/
      storage_repository.go      → StorageRepository interface + factory (mock / S3)

  service/
    model/
      analysis_dtos.go           → Finding, AnalysisResult, severity constants
      rule.go                    → Rule interface
    git_webhook_service.go       → GitWebhookService (pipeline orchestration)
    agentic_analysis_service.go  → Stub

    static_analysis/
      service.go                 → Public Service interface + NewService()
      engine.go                  → Private engine struct + EngineOption + RunAnalysis impl
      rule_registry.go           → Global rule registry (map[string][]model.Rule)
      static_analysis_service_test.go
      languages/python/
        parser.go                → PythonAST (tree-sitter parsing)
        rules/                   → 11 rule files + 11 test files

  utils/
    repo_download_utils.go       → Git clone (shallow) + zip
    file_utils.go                → File walking, extension filtering, language normalization

resources/
  test/                          → Python test fixtures for rule validation
```

---

## 4. Architecture & Design Patterns

### 4.1 Layered Architecture

```
HTTP Layer (controller/) → Service Layer (service/) → Repository Layer (repositories/)
                                  ↓
                          Static Analysis Engine
                          (service/static_analysis/)
```

### 4.2 Dependency Injection

All dependencies are wired in `cmd/api/setup/resources.go` via constructor injection. The `Resources` struct holds all initialized components:

- `DatabaseClient` (interface)
- `StorageRepository` (interface)
- `static_analysis.Service` (interface)
- `GitWebhookService` (interface)
- `Authenticator` / `WebhookSignatureValidator` (interfaces)

### 4.3 Static Analysis — Interface / Implementation Separation

```
service.go    → Service interface (public contract)
                  └── RunAnalysis(ctx, analysisID, files) → (*model.AnalysisResult, error)

engine.go     → engine struct (private, implements Service)
                  └── Configured via EngineOption functional options
                  └── WithOutputDir(dir), WithPersistence(bool)

NewService()  → Public constructor, returns Service backed by engine
```

### 4.4 Shared Types (`internal/service/model/`)

All rule implementations and the engine share types from this package:

- **`Finding`** — `rule_id`, `message`, `file_path`, `line`, `severity`, `snippet`
- **`AnalysisResult`** — `analysis_id`, `files_analyzed`, `findings []Finding`
- **`Rule`** interface — `ID()`, `Description()`, `AppliesToLanguage()`, `Evaluate(ast) ([]Finding, error)`
- **Severity constants** — `critical`, `high`, `medium`, `low`, `info`

### 4.5 Rule Registry

Global registry in `rule_registry.go`:

```go
var registry = map[string][]model.Rule{}
func RegisterRule(language string, rule model.Rule)
func GetRules(language string) []model.Rule
```

Rules self-register via `init()` functions. Currently only `LanguagePython = "python"` is defined.

### 4.6 Functional Options Pattern

The `engine` is configured at construction time:

```go
service := static_analysis.NewService(
    static_analysis.WithOutputDir("/tmp/results"),
    static_analysis.WithPersistence(false),
)
```

---

## 5. Data Models

### 5.1 AnalysisEntity (SQLite — GORM)

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT (PK) | UUID v4 |
| `repo_url` | TEXT (NOT NULL) | Git clone URL |
| `branch` | TEXT | Default: `main` |
| `commit_sha` | TEXT | Commit hash |
| `source_archive_path` | TEXT | S3 key for zipped source |
| `static_result_path` | TEXT | S3 key for JSON findings |
| `agent_result_path` | TEXT | S3 key (reserved for agentic results) |
| `status` | TEXT (NOT NULL, indexed) | See status lifecycle below |
| `error_message` | TEXT | Error details if failed |
| `created_at` | DATETIME | Auto-managed |
| `updated_at` | DATETIME | Auto-managed |
| `deleted_at` | DATETIME (indexed) | Soft delete |

**Status lifecycle:**

```
created → downloading_repo → uploading_source → parsing_files
  → static_analysis_running → static_analysis_done
  → waiting_agent_analysis → agent_analysis_running → agent_analysis_done
  → completed
  → failed (from any state)
```

### 5.2 Request / Response DTOs

**`WebHookRequestDTO`** (manual trigger):
```json
{ "repo_url": "https://github.com/user/repo.git", "branch": "main", "commit": "abc123" }
```

**`GitHubPushPayload`** (webhook):
```json
{ "ref": "refs/heads/main", "after": "abc123", "repository": { "clone_url": "..." } }
```

**`WebHookResponseDTO`**:
```json
{ "analysis_id": "uuid", "status": "created", "message": "...", "timestamp": "..." }
```

**`ErrorResponseDTO`**:
```json
{ "error": "error_type", "message": "description" }
```

### 5.3 Finding (JSON output)

```json
{
  "rule_id": "MCP-DTI-002",
  "message": "Command injection via os.system()",
  "file_path": "server.py",
  "line": 42,
  "severity": "high",
  "snippet": "os.system(user_input)"
}
```

### 5.4 AnalysisResult (JSON output)

```json
{
  "analysis_id": "uuid",
  "files_analyzed": 12,
  "findings": [ /* ...Finding objects */ ]
}
```

---

## 6. API Endpoints

| Method | Path | Auth | Request Body | Response | Status |
|--------|------|------|-------------|----------|--------|
| `POST` | `/v1/webhook/github` | HMAC-SHA256 | `GitHubPushPayload` | `WebHookResponseDTO` | 202 |
| `POST` | `/v1/analysis` | API Key | `WebHookRequestDTO` | `WebHookResponseDTO` | 202 |
| `GET` | `/v1/analysis/{id}/status` | API Key | — | `AnalysisStatusDTO` | 200 |
| `GET` | `/v1/analysis/{id}/result` | API Key | — | `AnalysisResult` (JSON) | 200 |
| `POST` | `/v1/agentic_analysis` | API Key | — | 501 Not Implemented | — |
| `GET` | `/health` | None | — | 200 OK | 200 |

---

## 7. Authentication

### 7.1 Webhook HMAC-SHA256

- Header: `X-Hub-Signature-256`
- Computes `HMAC-SHA256(body, secret)` and compares with header value
- Secret from env var: `GITHUB_WEBHOOK_SECRET`

### 7.2 API Key

- Headers: `X-API-Key`, `X-Client-ID`
- Validates against env var `MCPGUARD_API_KEYS` (format: `client_id:api_key,client_id2:api_key2`)

---

## 8. Configuration

Embedded YAML files selected via `SCOPE` environment variable:

| Scope | File | DB Mode | Storage Mode |
|-------|------|---------|-------------|
| `local` / default | `config/default.yaml` | In-memory SQLite | Local filesystem |
| `prod` | `config/prod.yaml` | File SQLite | AWS S3 |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_WEBHOOK_SECRET` | Yes (for webhooks) | HMAC-SHA256 shared secret |
| `MCPGUARD_API_KEYS` | Yes (for API key auth) | `client_id:key,...` |
| `SCOPE` | No | Config profile selector |

---

## 9. Static Analysis Engine — Processing Flow

```
1. RunAnalysis(ctx, analysisID, files)
2. For each SourceFileDTO:
   a. Check ctx cancellation
   b. Get rules for file.Language from registry
   c. Parse AST (tree-sitter for Python)
   d. For each rule: rule.Evaluate(ast) → []Finding
   e. Set finding.FilePath from SourceFileDTO
   f. Append findings
3. Build AnalysisResult{AnalysisID, Files, Findings}
4. If persistResults: save JSON to outputDir
5. Return *AnalysisResult
```

### Supported Languages for AST Parsing

| Language | Parser | Rules |
|----------|--------|-------|
| Python | tree-sitter (CGO) | 31 attack patterns in 11 rule files |
| JSON, YAML, TOML, Markdown | Parsed (file content read) | No rules registered yet |

---

## 10. Security Rules — Implementation Pattern

Each rule file follows a consistent pattern:

```go
type CommandInjectionRule struct{}

func NewCommandInjectionRule() model.Rule { return &CommandInjectionRule{} }
func (r *CommandInjectionRule) ID() string { return "MCP-DTI-002" }
func (r *CommandInjectionRule) Description() string { return "..." }
func (r *CommandInjectionRule) AppliesToLanguage() string { return "python" }
func (r *CommandInjectionRule) Evaluate(ast interface{}) ([]model.Finding, error) {
    // Cast ast to *python.PythonAST
    // Walk tree-sitter nodes
    // Match patterns (regex + AST node types)
    // Return findings with severity, line, snippet
}

func init() {
    static_analysis.RegisterRule(static_analysis.LanguagePython, NewCommandInjectionRule())
}
```

---

## 11. Planned Components (Not Yet Implemented)

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Agentic Analysis API | Python 3.11+ | LLM-based semantic security analysis |
| Message Queue | RabbitMQ (AMQP) | Async job distribution, horizontal scaling |
| CI/CD Integration | GitHub Actions | Auto-comment PR findings |
| Containerization | Docker / Docker Compose | Isolation, reproducibility |
| Observability | Prometheus + Grafana | Metrics, dashboards, alerting |
| Multi-language Rules | Go (tree-sitter grammars) | Extend beyond Python |
