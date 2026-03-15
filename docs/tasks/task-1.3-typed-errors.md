# Task 1.3: Typed Errors for Service Layer

| Field | Value |
|-------|-------|
| **ID** | task-1.3 |
| **Phase** | 1 — Server Hardening & Code Quality |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

The controller layer uses string matching (`strings.Contains(err.Error(), "not complete")`) to distinguish between different error types returned by the service layer. This is fragile — if the error message wording changes, the controller breaks silently.

### Expected Behavior

1. The service layer returns typed/sentinel errors for known error conditions.
2. The controller uses `errors.Is()` to check error types — no string matching.
3. HTTP status codes are correctly mapped to error types:
   - `ErrAnalysisNotFound` → 404 Not Found
   - `ErrAnalysisNotComplete` → 202 Accepted (still processing)

### Acceptance Criteria

- No `strings.Contains` used for error type detection in controllers.
- All service errors are either sentinel errors or wrapped sentinel errors.
- Controller returns correct HTTP status for each error type.

---

## Technical Specification

### Current State

**`internal/controller/git_webhook_controller.go` (line 144):**
```go
if strings.Contains(err.Error(), "not complete") {
    c.writeError(w, http.StatusAccepted, "analysis_pending", err.Error())
} else {
    c.writeError(w, http.StatusNotFound, "not_found", err.Error())
}
```

**`internal/service/git_webhook_service.go` (line 191–195):**
```go
if entity.Status != "static_done" && entity.Status != "completed" {
    return nil, fmt.Errorf("analysis not complete, current status: %s", entity.Status)
}
```

**`internal/service/git_webhook_service.go` (line 171):**
```go
return nil, fmt.Errorf("analysis not found: %w", err)
```

### Changes Required

#### 1. Create `internal/service/errors.go`

```go
package service

import "errors"

var (
    // ErrAnalysisNotFound is returned when an analysis ID does not exist in the database.
    ErrAnalysisNotFound = errors.New("analysis not found")

    // ErrAnalysisNotComplete is returned when results are requested for an analysis
    // that has not yet finished processing.
    ErrAnalysisNotComplete = errors.New("analysis not complete")
)
```

#### 2. Update `internal/service/git_webhook_service.go`

**`GetAnalysisStatus` (line 171):**
```go
// Before:
return nil, fmt.Errorf("analysis not found: %w", err)

// After:
return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
```

**`GetAnalysisResult` (lines 190–195):**
```go
// Before:
entity, err := uc.dbRepo.FindByID(ctx, analysisID)
if err != nil {
    return nil, fmt.Errorf("analysis not found: %w", err)
}
if entity.Status != "static_done" && entity.Status != "completed" {
    return nil, fmt.Errorf("analysis not complete, current status: %s", entity.Status)
}

// After:
entity, err := uc.dbRepo.FindByID(ctx, analysisID)
if err != nil {
    return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
}
if entity.Status != "static_done" && entity.Status != "completed" {
    return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
}
```

#### 3. Update `internal/controller/git_webhook_controller.go`

```go
// Before:
if strings.Contains(err.Error(), "not complete") {
    c.writeError(w, http.StatusAccepted, "analysis_pending", err.Error())
} else {
    c.writeError(w, http.StatusNotFound, "not_found", err.Error())
}

// After:
if errors.Is(err, service.ErrAnalysisNotComplete) {
    c.writeError(w, http.StatusAccepted, "analysis_pending", err.Error())
} else if errors.Is(err, service.ErrAnalysisNotFound) {
    c.writeError(w, http.StatusNotFound, "not_found", err.Error())
} else {
    c.writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}
```

Add `"errors"` import; remove `"strings"` import if no longer used.

### Files to Create

| File | Purpose |
|------|---------|
| `internal/service/errors.go` | Sentinel error definitions |

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/git_webhook_service.go` | Wrap errors with sentinels |
| `internal/controller/git_webhook_controller.go` | Use `errors.Is()` instead of `strings.Contains` |

### Testing

- Request results for a non-existent analysis ID → expect 404.
- Request results for an in-progress analysis → expect 202.
- Existing controller test (`git_webhook_controller_test.go`) should still pass.
