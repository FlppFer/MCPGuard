# CLAUDE.md — MCPGuard Coding Guidelines

## Project Overview

MCPGuard is a Go REST API for automated static security analysis of MCP server implementations. Module path: `github.com/FlppFer/MCPGuard`.

## Core Engineering Principles

### SOLID
- **Single Responsibility:** Each struct, function, and file has one clear purpose. Split when responsibilities grow.
- **Open/Closed:** Extend behavior through interfaces and new implementations — don't modify existing working code to add features (e.g., new rules implement `model.Rule` without touching the engine).
- **Liskov Substitution:** Any implementation of an interface must be fully substitutable (mocks included).
- **Interface Segregation:** Keep interfaces small and focused. Prefer multiple narrow interfaces over one large one.
- **Dependency Inversion:** Depend on abstractions (interfaces), not concretions. All service/repository dependencies are injected as interfaces.

### KISS — Keep It Simple
- Favor the simplest solution that solves the problem correctly.
- Avoid premature abstractions — extract only when a pattern repeats or a clear need exists.
- If a piece of logic requires a comment to explain *what* it does (not *why*), it should be refactored to be self-explanatory.

### DRY — Don't Repeat Yourself
- Extract shared logic into helper functions or shared packages (`utils/`, `service/model/`).
- Reuse existing sentinel errors, DTOs, and constants — never redefine them.
- If the same pattern appears in 3+ places, refactor it into a common abstraction.

### Readability & Maintainability
- **Small functions:** Functions should do one thing. Aim for ≤ 20–30 lines per function. If a function grows beyond that, extract sub-steps into well-named helpers.
- **Descriptive names:** Function and variable names should make the code readable without comments. Prefer `uploadAnalysisResult` over `upload` or `doWork`.
- **Early returns:** Use guard clauses and early returns to reduce nesting. Avoid deep `if/else` chains.
- **Vertical slicing:** Group related logic together within a file. Keep public API at the top, private helpers below.
- **Minimize cognitive load:** A reader should understand any single function without scrolling or jumping to multiple other files.

## Documentation

- **Always read** `docs/PROJECT.md`, `docs/FUNCTIONAL_SPECS.md`, and `docs/TECHNICAL_SPECS.md` before making architectural decisions.
- **Task definitions** live in `docs/tasks/`. Check `docs/tasks/tasks_status.json` for current status before starting work.
- Update `tasks_status.json` when completing a task.

## Architecture & Package Layout

```
cmd/api/              → Entrypoint + bootstrap (main.go, setup/)
config/               → Embedded YAML config (go:embed)
internal/
  controller/         → HTTP handlers (chi router)
  middleware/         → General middleware (request_id.go)
  middleware/auth/    → Auth strategies (webhook HMAC, API key)
  model/
    http/             → Request/response DTOs
    services/         → Service-layer DTOs
    repositories/     → GORM entities
  repositories/
    db/               → Database interface + implementations
    obj_storage/      → Object storage interface + implementations
  service/            → Business logic (orchestration)
    model/            → Shared types (Finding, Rule, AnalysisResult)
    static_analysis/  → Analysis engine + rule registry
      languages/      → Per-language parsers and rules
  utils/              → Shared utilities (git clone, file walking)
resources/test/       → Test fixtures
```

## Design Patterns — Follow These Strictly

### Interface-First Design
- Define a **public interface** in its own file (e.g., `service.go`) and keep the **private implementation** in a separate file (e.g., `engine.go`).
- Constructors return the interface type, not the concrete struct: `func NewService(...) Service`.
- External callers never reference the private struct.

### Functional Options
- Use `type Option func(*struct)` pattern for configurable constructors.
- Example: `WithOutputDir(dir)`, `WithPersistence(bool)`.

### Dependency Injection
- All dependencies are wired via constructor injection in `cmd/api/setup/resources.go`.
- Services, repositories, and middleware receive their dependencies as interface parameters.
- Never use global state for dependencies.

### Sentinel Errors
- Define typed/sentinel errors in `errors.go` within the relevant package (e.g., `internal/service/errors.go`).
- Use `fmt.Errorf("%w: ...", ErrSentinel)` to wrap sentinel errors with context.
- Controllers use `errors.Is()` — **never** `strings.Contains` on error messages.

### Rule Registration
- Security rules self-register via `init()` functions calling `static_analysis.RegisterRule()`.
- Each rule implements the `model.Rule` interface: `ID()`, `Description()`, `AppliesToLanguage()`, `Evaluate()`.
- Each rule file has a corresponding `_test.go` file.

## Coding Conventions

### Logging
- Use `log/slog` exclusively. **Never** import `"log"` (stdlib).
- Always include structured fields: `slog.Info("msg", "key", value, "key2", value2)`.
- Include `"analysis_id"` in all analysis-related log entries.
- Include `"error"` field when logging errors.
- Log levels: `Debug` for tracing, `Info` for operations, `Warn` for non-fatal issues, `Error` for failures.

### Error Handling
- Return `error` — never `panic` in library/service code. `panic` is only acceptable for unrecoverable bootstrap failures in `main.go` or `setup/`.
- Wrap errors with context: `fmt.Errorf("failed to do X: %w", err)`.
- Use sentinel errors for known conditions that callers need to distinguish.

### HTTP Handlers
- Handlers are methods on the controller struct that return `http.HandlerFunc`.
- Use `chi.URLParam(r, "id")` for path parameters.
- Response helpers: `writeJSON(w, status, data)` and `writeError(w, status, code, message)`.
- Always set `Content-Type: application/json; charset=UTF-8`.

### Context
- Pass `context.Context` as the first parameter to all service and repository methods.
- Use `context.Background()` for goroutines that outlive the HTTP request.
- Use `context.WithValue` with unexported key types for request-scoped values (e.g., request ID).

### Naming
- Interfaces: descriptive nouns (e.g., `Service`, `DatabaseClient`, `Authenticator`).
- Interface files: named after the concept (e.g., `service.go`, `types.go`).
- Implementations: unexported structs (e.g., `engine`, `gitWebhookServiceImpl`).
- DTOs: suffixed with `DTO` (e.g., `SourceFileDTO`, `WebHookResponseDTO`).
- Entity types: suffixed with `Entity` (e.g., `AnalysisEntity`).
- Test files: `_test.go` suffix in the same package.

### Imports
- Group imports: stdlib → external → internal. Separated by blank lines.
- Use named imports only when needed to resolve ambiguity (e.g., `authMiddleware`, `httpmodel`).

## Testing

### Coverage Target
- **Minimum 90% code coverage** across the full codebase.
- Measure with: `go test -coverprofile=coverage.out ./...`
- Coverage below 90% blocks merges.

### Test Patterns
- Use **table-driven tests** for handlers and service methods.
- Mock external dependencies via interfaces (never hit real DB/S3 in unit tests).
- Mock structs use function fields for flexible per-test behavior:
  ```go
  type mockService struct {
      doThingFunc func(ctx context.Context, id string) (Result, error)
  }
  ```
- Test file naming: `<filename>_test.go` in the same package.
- Test fixtures live in `resources/test/`.

### What to Test
- Every controller handler: success path, validation errors, each sentinel error mapping.
- Every service method: success, each error branch, edge cases.
- Every security rule: detection of true positives, absence of false positives.
- Middleware: header propagation, context value injection.

## Middleware
- General middleware (request ID, logging) lives in `internal/middleware/`.
- Auth middleware lives in `internal/middleware/auth/`.
- Register global middleware on the router before route groups.
- Auth middleware is scoped to route groups.

## Configuration
- Config is embedded YAML selected by `SCOPE` env var (`local` → `default.yaml`, `prod` → `prod.yaml`).
- Secrets come from environment variables — never hardcode them.
- `LogLevel` from config is applied to `slog` at startup.

## Git & Workflow
- Check `docs/tasks/tasks_status.json` before starting any task.
- Tasks are organized by phase; respect dependency ordering.
- After completing a task, update `tasks_status.json`.
