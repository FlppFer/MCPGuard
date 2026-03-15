# Task 1.4: Request ID Middleware

| Field | Value |
|-------|-------|
| **ID** | task-1.4 |
| **Phase** | 1 — Server Hardening & Code Quality |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

When multiple analyses run concurrently, there is no way to correlate log entries to specific HTTP requests. This makes debugging production issues very difficult.

### Expected Behavior

1. Every incoming HTTP request is assigned a unique request ID.
2. If the client sends an `X-Request-ID` header, that value is used; otherwise a new UUID is generated.
3. The request ID is included in the response as an `X-Request-ID` header.
4. The request ID is available in the request context for use in log calls.
5. All log entries within a request's lifecycle include the `request_id` field.

### Acceptance Criteria

- Every response includes `X-Request-ID` header.
- Log entries from controllers and services include `request_id`.
- Client-provided `X-Request-ID` is respected (pass-through).

---

## Technical Specification

### Changes Required

#### 1. Create `internal/middleware/request_id.go`

```go
package middleware

import (
    "context"
    "net/http"

    "github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// RequestID is a middleware that assigns a unique ID to each request.
func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get(RequestIDHeader)
        if id == "" {
            id = uuid.NewString()
        }

        w.Header().Set(RequestIDHeader, id)

        ctx := context.WithValue(r.Context(), requestIDKey{}, id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
    if id, ok := ctx.Value(requestIDKey{}).(string); ok {
        return id
    }
    return ""
}
```

#### 2. Register middleware in `cmd/api/setup/routes.go`

Add as the **first** middleware on the router (before auth):

```go
func NewRouter(resources *Resources) *chi.Mux {
    r := chi.NewRouter()
    r.Use(customMiddleware.RequestID)  // first middleware — assigns request ID
    // ... rest of routes ...
}
```

#### 3. Usage in service/controller log calls

```go
slog.Info("Analysis started",
    "request_id", middleware.GetRequestID(ctx),
    "analysis_id", analysisID,
)
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/middleware/request_id.go` | Request ID middleware + context helper |

### Files to Modify

| File | Change |
|------|--------|
| `cmd/api/setup/routes.go` | Register `RequestID` middleware on router |

### Testing

- Send request without `X-Request-ID` → response contains a generated UUID in `X-Request-ID`.
- Send request with `X-Request-ID: my-id-123` → response contains `X-Request-ID: my-id-123`.
