# Task 3.3: Agentic Analysis Controller

| Field | Value |
|-------|-------|
| **ID** | task-3.3 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | High |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | task-3.2 (Agentic Analysis Service) |

---

## Functional Specification

### Problem Statement

`agentic_analysis_controller.go` currently has a single endpoint that returns 501 Not Implemented. It has no dependency on the agentic service and no real functionality.

### Expected Behavior

1. `POST /v1/agentic_analysis` — **Callback endpoint**: receives analysis results from the Python worker. Validates the payload and calls `service.ReceiveResult()`.
2. `GET /v1/agentic_analysis/{id}/result` — **Result retrieval**: returns stored agentic findings for a given analysis ID.

### Acceptance Criteria

- `POST /v1/agentic_analysis` accepts `AgenticAnalysisResultDTO` JSON and returns 200 on success.
- `POST /v1/agentic_analysis` with invalid payload returns 400.
- `GET /v1/agentic_analysis/{id}/result` returns stored agentic JSON or 404.
- Both endpoints require API Key authentication.

---

## Technical Specification

### Current State

**`internal/controller/agentic_analysis_controller.go`:**
```go
type agenticAnalysisController struct{}

func NewAgenticAnalysisController() AgenticAnalysisControllerInterface {
    return &agenticAnalysisController{}
}

func (c *agenticAnalysisController) RequestAgenticAnalysis() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        c.writeError(w, http.StatusNotImplemented, "not_implemented", "Agentic analysis endpoint not yet implemented")
    }
}
```

No service injected. No real handlers.

### Changes Required

#### 1. Update interface and constructor

```go
type AgenticAnalysisControllerInterface interface {
    ReceiveAgenticResult() http.HandlerFunc  // POST /v1/agentic_analysis
    GetAgenticResult() http.HandlerFunc      // GET  /v1/agentic_analysis/{id}/result
}

type agenticAnalysisController struct {
    agenticService service.AgenticAnalysisService
}

func NewAgenticAnalysisController(agenticService service.AgenticAnalysisService) AgenticAnalysisControllerInterface {
    return &agenticAnalysisController{
        agenticService: agenticService,
    }
}
```

#### 2. Implement `ReceiveAgenticResult`

```go
func (c *agenticAnalysisController) ReceiveAgenticResult() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var result httpmodel.AgenticAnalysisResultDTO
        if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
            c.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request body")
            return
        }
        if result.AnalysisID == "" {
            c.writeError(w, http.StatusBadRequest, "missing_field", "analysis_id is required")
            return
        }
        if err := c.agenticService.ReceiveResult(r.Context(), &result); err != nil {
            slog.Error("Failed to process agentic result", "error", err, "analysis_id", result.AnalysisID)
            c.writeError(w, http.StatusInternalServerError, "processing_failed", err.Error())
            return
        }
        c.writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
    }
}
```

#### 3. Implement `GetAgenticResult`

```go
func (c *agenticAnalysisController) GetAgenticResult() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        analysisID := chi.URLParam(r, "id")
        if analysisID == "" {
            c.writeError(w, http.StatusBadRequest, "missing_id", "Analysis ID is required")
            return
        }
        data, err := c.agenticService.GetResult(r.Context(), analysisID)
        if err != nil {
            c.writeError(w, http.StatusNotFound, "not_found", err.Error())
            return
        }
        w.Header().Set("Content-Type", "application/json; charset=UTF-8")
        w.WriteHeader(http.StatusOK)
        w.Write(data)
    }
}
```

#### 4. Update bootstrap and routes

**`cmd/api/setup/resources.go`:**
- Create `AgenticAnalysisService` from config.
- Pass it to `NewAgenticAnalysisController(agenticService)`.

**`cmd/api/setup/routes.go`:**
- Replace current `r.Post("/agentic_analysis", ...)` with `ReceiveAgenticResult()`.
- Add `r.Get("/agentic_analysis/{id}/result", ...)`.

### Files to Modify

| File | Change |
|------|--------|
| `internal/controller/agentic_analysis_controller.go` | Full rewrite with service dependency |
| `cmd/api/setup/resources.go` | Wire `AgenticAnalysisService` into controller |
| `cmd/api/setup/routes.go` | Register new routes |

### Testing

- POST valid `AgenticAnalysisResultDTO` → expect 200.
- POST missing `analysis_id` → expect 400.
- GET with valid ID after POST → expect stored JSON.
- GET with unknown ID → expect 404.
