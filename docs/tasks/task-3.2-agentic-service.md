# Task 3.2: Agentic Analysis Service Interface

| Field | Value |
|-------|-------|
| **ID** | task-3.2 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | High |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-3.1 (Agentic Analysis DTOs) |

---

## Functional Specification

### Problem Statement

`internal/service/agentic_analysis_service.go` is an empty file (only `package service`). The Go API has no service-layer logic for submitting jobs to the Python worker, receiving results, or retrieving stored agentic findings.

### Expected Behavior

1. The service can submit an analysis job to the Python agentic worker (initially via HTTP POST).
2. The service can receive and persist results returned by the Python worker.
3. The service can retrieve stored agentic results by analysis ID.
4. If the Python worker is unreachable, the error is logged and the overall analysis continues (agentic is optional/complementary).

### Acceptance Criteria

- `AgenticAnalysisService` interface is defined with `SubmitForAnalysis`, `ReceiveResult`, and `GetResult` methods.
- A concrete implementation exists that sends HTTP POST to a configured worker URL.
- `ReceiveResult` uploads findings JSON to S3 and updates the analysis entity status.
- Config includes agentic worker URL and enabled flag.

---

## Technical Specification

### Current State

**`internal/service/agentic_analysis_service.go`:**
```go
package service
// (empty)
```

### Changes Required

#### 1. Define interface and implementation in `agentic_analysis_service.go`

```go
package service

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "path/filepath"
    "time"

    httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
    "github.com/FlppFer/MCPGuard/internal/repositories/db"
    "github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
)

type AgenticAnalysisService interface {
    // SubmitForAnalysis sends an analysis job to the Python agentic worker.
    SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error

    // ReceiveResult processes and persists results from the Python worker.
    ReceiveResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error

    // GetResult retrieves stored agentic analysis results for an analysis ID.
    GetResult(ctx context.Context, analysisID string) ([]byte, error)
}

type agenticAnalysisServiceImpl struct {
    dbRepo      db.DatabaseClient
    storageRepo obj_storage.StorageRepository
    workerURL   string        // e.g., "http://python-worker:5000"
    httpClient  *http.Client
    enabled     bool
}

func NewAgenticAnalysisService(
    dbRepo db.DatabaseClient,
    storageRepo obj_storage.StorageRepository,
    workerURL string,
    enabled bool,
) AgenticAnalysisService {
    return &agenticAnalysisServiceImpl{
        dbRepo:      dbRepo,
        storageRepo: storageRepo,
        workerURL:   workerURL,
        httpClient:  &http.Client{Timeout: 30 * time.Second},
        enabled:     enabled,
    }
}
```

#### 2. Implement `SubmitForAnalysis`

```go
func (s *agenticAnalysisServiceImpl) SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error {
    if !s.enabled {
        slog.Debug("Agentic analysis disabled, skipping submission", "analysis_id", req.AnalysisID)
        return nil
    }

    body, err := json.Marshal(req)
    if err != nil {
        return fmt.Errorf("failed to marshal agentic request: %w", err)
    }

    url := fmt.Sprintf("%s/analyze", s.workerURL)
    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("failed to create HTTP request: %w", err)
    }
    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := s.httpClient.Do(httpReq)
    if err != nil {
        return fmt.Errorf("failed to submit to agentic worker: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return fmt.Errorf("agentic worker returned status %d", resp.StatusCode)
    }

    slog.Info("Agentic analysis submitted", "analysis_id", req.AnalysisID, "worker_url", url)
    return nil
}
```

#### 3. Implement `ReceiveResult`

Serializes result to JSON, uploads to S3 as `analysis-results/{id}_agentic.json`, and updates the DB entity status to `agent_analysis_done`.

#### 4. Implement `GetResult`

Downloads `analysis-results/{id}_agentic.json` from S3 and returns raw bytes.

#### 5. Config changes

**`config/config.go`** — add:
```go
type AgenticConfig struct {
    Enabled   bool   `yaml:"enabled"`
    WorkerURL string `yaml:"worker_url"`
}
```

Add `AgenticCfg *AgenticConfig \`yaml:"agentic"\`` to `Config` struct.

**`config/default.yaml`** — add:
```yaml
agentic:
  enabled: false
  worker_url: "http://localhost:5000"
```

**`config/prod.yaml`** — add:
```yaml
agentic:
  enabled: true
  worker_url: "http://python-worker:5000"
```

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/agentic_analysis_service.go` | Full interface + implementation |
| `config/config.go` | Add `AgenticConfig` struct |
| `config/default.yaml` | Add `agentic` section |
| `config/prod.yaml` | Add `agentic` section |

### Testing

- Unit test with mock HTTP server returning 200 → verify `SubmitForAnalysis` succeeds.
- Unit test with mock HTTP server returning 500 → verify error is returned.
- Unit test `ReceiveResult` → verify JSON is uploaded to mock storage.
