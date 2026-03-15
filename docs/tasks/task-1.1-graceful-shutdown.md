# Task 1.1: Graceful Shutdown

| Field | Value |
|-------|-------|
| **ID** | task-1.1 |
| **Phase** | 1 — Server Hardening & Code Quality |
| **Priority** | High |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

When the MCPGuard API process receives a termination signal (SIGINT/SIGTERM), the server shuts down immediately. Any in-flight HTTP requests are dropped mid-response, and background goroutines running static analysis are terminated without completing their work. This can leave analysis entities in an inconsistent state (e.g., stuck at `static_analysis_started` forever).

### Expected Behavior

1. On receiving SIGINT or SIGTERM, the server stops accepting **new** connections.
2. All in-flight HTTP requests are allowed to complete (up to a configurable timeout, e.g., 30 seconds).
3. A log message is emitted indicating the server is shutting down.
4. After all requests complete (or timeout expires), the process exits cleanly with code 0.
5. If the timeout expires before all requests complete, the process exits with a warning log.

### Acceptance Criteria

- Server responds to `SIGINT` / `SIGTERM` with graceful drain.
- Requests that started before the signal complete successfully.
- New connections after the signal are refused.
- Server logs `"Shutting down gracefully..."` and `"Server stopped"` messages.

---

## Technical Specification

### Current State

**`cmd/api/main.go`:**
```go
func run(ctx context.Context) error {
    slog.Debug("MCPGuard - Initializing server")
    cfg, err := config.LoadConfig()
    if err != nil { panic(err) }
    resources := setup.Bootstrap(ctx, cfg)
    fmt.Println("MCPGuard - Initializing server")
    setup.InitRoutes(resources)
    return nil
}
```

**`cmd/api/setup/routes.go`:**
```go
func InitRoutes(resources *Resources) {
    slog.Info("Initializing routes")
    r := chi.NewRouter()
    // ... route registration ...
    slog.Info("Starting HTTP server", "port", 8080)
    err := http.ListenAndServe(":8080", r)
    if err != nil { panic(err) }
}
```

`InitRoutes` both builds the router AND starts the server, blocking until crash. No shutdown handling.

### Changes Required

#### 1. Refactor `cmd/api/setup/routes.go`

Change `InitRoutes` to **return** the router instead of starting the server:

```go
// NewRouter builds and returns the configured chi.Mux (does NOT start serving).
func NewRouter(resources *Resources) *chi.Mux {
    slog.Info("Initializing routes")
    r := chi.NewRouter()

    r.Route("/v1", func(r chi.Router) {
        r.Group(func(r chi.Router) {
            r.Use(middleware.WebhookAuth(resources.WebhookAuthenticator))
            r.Post("/webhook/github", resources.GitWebhookController.HandleGitHubWebhook())
        })
        r.Group(func(r chi.Router) {
            r.Use(middleware.Auth(resources.APIKeyAuthenticator))
            r.Post("/analysis", resources.GitWebhookController.StartAnalysis())
            r.Get("/analysis/{id}/status", resources.GitWebhookController.GetAnalysisStatus())
            r.Get("/analysis/{id}/result", resources.GitWebhookController.GetAnalysisResult())
            r.Post("/agentic_analysis", resources.AgenticAnalysisController.RequestAgenticAnalysis())
        })
    })

    r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    })

    return r
}
```

#### 2. Refactor `cmd/api/main.go`

Add signal handling and `http.Server` lifecycle:

```go
func run(ctx context.Context) error {
    slog.Debug("MCPGuard - Initializing server")

    cfg, err := config.LoadConfig()
    if err != nil {
        return fmt.Errorf("failed to load config: %w", err)
    }

    resources := setup.Bootstrap(ctx, cfg)
    router := setup.NewRouter(resources)

    srv := &http.Server{
        Addr:    ":8080",
        Handler: router,
    }

    // Start server in goroutine
    go func() {
        slog.Info("Starting HTTP server", "port", 8080)
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            slog.Error("HTTP server error", "error", err)
        }
    }()

    // Wait for interrupt signal
    ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
    defer stop()
    <-ctx.Done()

    slog.Info("Shutting down gracefully...")

    // Give in-flight requests 30 seconds to complete
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(shutdownCtx); err != nil {
        slog.Error("Forced shutdown", "error", err)
        return err
    }

    slog.Info("Server stopped")
    return nil
}
```

#### 3. New imports needed in `main.go`

```go
import (
    "os"
    "os/signal"
    "syscall"
    "time"
    "net/http"
)
```

### Files to Modify

| File | Change |
|------|--------|
| `cmd/api/main.go` | Add signal handling, `http.Server` lifecycle, remove `fmt.Println` |
| `cmd/api/setup/routes.go` | Rename `InitRoutes` → `NewRouter`, return `*chi.Mux` instead of blocking |

### Testing

- Start the server, send a long-running analysis request, then `Ctrl+C`. Verify the analysis completes.
- Start the server, `Ctrl+C` immediately. Verify clean exit with log messages.
