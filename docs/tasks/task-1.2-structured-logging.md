# Task 1.2: Consistent Structured Logging

| Field | Value |
|-------|-------|
| **ID** | task-1.2 |
| **Phase** | 1 — Server Hardening & Code Quality |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

The codebase uses two different logging libraries: `log.Println`/`log.Printf` (Go stdlib) in the service layer and `slog` (structured logging) in controllers and middleware. This inconsistency makes logs harder to parse, filter, and correlate in production environments.

### Expected Behavior

1. All log output uses `log/slog` exclusively.
2. Log entries include structured fields (`"analysis_id"`, `"error"`, `"repo_url"`, etc.) for machine-parseable output.
3. Log level is configurable via the `log-level` field in the YAML config (currently defined but not wired).
4. Debug-level logs are suppressed in production (`prod.yaml` uses `"error"` level).

### Acceptance Criteria

- No imports of `"log"` package remain in the codebase (only `"log/slog"`).
- All log calls include relevant structured fields.
- `cfg.LogLevel` is applied to the default `slog` handler at startup.

---

## Technical Specification

### Current State

**Occurrences of stdlib `log` in `internal/service/git_webhook_service.go`:**

```go
// Line 4
import "log"

// Line 113
log.Println("Static analysis failed:", err)

// Line 121
log.Println("Failed to upload analysis results:", err)

// Line 163
log.Printf("Analysis results uploaded to storage: %s", s3Key)
```

**Config already defines log level but it's never applied:**

```yaml
# config/default.yaml
log-level: "debug"

# config/prod.yaml
log-level: "error"
```

```go
// config/config.go
type Config struct {
    LogLevel string `yaml:"log-level"`
    // ...
}
```

### Changes Required

#### 1. Configure slog in `cmd/api/main.go`

Add at the beginning of `run()`:

```go
func configureSlog(levelStr string) {
    var level slog.Level
    switch strings.ToLower(levelStr) {
    case "debug":
        level = slog.LevelDebug
    case "info":
        level = slog.LevelInfo
    case "warn", "warning":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    default:
        level = slog.LevelInfo
    }
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
    slog.SetDefault(slog.New(handler))
}
```

Call `configureSlog(cfg.LogLevel)` right after `LoadConfig()`.

#### 2. Replace `log` with `slog` in `git_webhook_service.go`

| Before | After |
|--------|-------|
| `log.Println("Static analysis failed:", err)` | `slog.Error("Static analysis failed", "analysis_id", analysisID, "error", err)` |
| `log.Println("Failed to upload analysis results:", err)` | `slog.Error("Failed to upload analysis results", "analysis_id", analysisID, "error", err)` |
| `log.Printf("Analysis results uploaded to storage: %s", s3Key)` | `slog.Info("Analysis results uploaded to storage", "analysis_id", analysisID, "s3_key", s3Key)` |

Remove the `"log"` import and add `"log/slog"`.

#### 3. Search for any other `log.Print` occurrences

Run: `grep -r "\"log\"" internal/` — replace any remaining stdlib log imports.

### Files to Modify

| File | Change |
|------|--------|
| `cmd/api/main.go` | Add `configureSlog()` function, call after config load |
| `internal/service/git_webhook_service.go` | Replace `log` → `slog`, add structured fields |

### Testing

- Run with `SCOPE=local` (debug level) — verify debug messages appear.
- Run with `SCOPE=prod` (error level) — verify only errors appear.
- Verify log output is valid JSON (one object per line).
