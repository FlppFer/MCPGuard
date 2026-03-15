# Task 3.1: Agentic Analysis DTOs

| Field | Value |
|-------|-------|
| **ID** | task-3.1 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | High |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

No data structures exist for communicating agentic (AI-based) analysis requests and responses between the Go API and the planned Python agentic worker. Before the service or controller can be implemented, the contract (DTOs) must be defined.

### Expected Behavior

1. A request DTO defines what information is sent to the Python agentic worker to start an analysis.
2. A result DTO defines the structure the Python worker returns after completing semantic analysis.
3. A finding DTO defines individual findings from the agentic analysis, including a confidence score.

### Acceptance Criteria

- DTOs are defined and compile without errors.
- DTOs use JSON struct tags consistent with the existing codebase conventions.
- The agentic finding DTO includes a `confidence` field (0.0–1.0) to distinguish from deterministic static findings.

---

## Technical Specification

### Context

The MCPGuard article describes a Python-based AI agent that performs semantic analysis using LLMs specialized in cybersecurity. The Go API needs to:
1. Send a job description to the Python worker (analysis ID, repo location in S3).
2. Receive structured findings back from the worker.

The communication can be direct HTTP (initially) or via RabbitMQ (Phase 4).

### Create `internal/model/http/agentic_analysis_dtos.go`

```go
package http

import "time"

// AgenticAnalysisRequestDTO is sent to the Python agentic worker to start analysis.
type AgenticAnalysisRequestDTO struct {
    AnalysisID string `json:"analysis_id"`
    RepoURL    string `json:"repo_url"`
    Branch     string `json:"branch"`
    Commit     string `json:"commit"`
    SourceKey  string `json:"source_key"` // S3 key for the zipped source archive
}

// AgenticAnalysisResultDTO is received from the Python worker after analysis completes.
type AgenticAnalysisResultDTO struct {
    AnalysisID string               `json:"analysis_id"`
    Findings   []AgenticFindingDTO  `json:"findings"`
    Summary    string               `json:"summary"`
    ModelUsed  string               `json:"model_used,omitempty"` // e.g., "gpt-4", "claude-3"
    Timestamp  time.Time            `json:"timestamp"`
}

// AgenticFindingDTO represents a single finding from the AI-based semantic analysis.
type AgenticFindingDTO struct {
    Category    string  `json:"category"`    // e.g., "tool_poisoning", "data_exfiltration"
    Description string  `json:"description"` // Human-readable explanation
    FilePath    string  `json:"file_path"`
    StartLine   int     `json:"start_line,omitempty"`
    EndLine     int     `json:"end_line,omitempty"`
    Severity    string  `json:"severity"`    // critical, high, medium, low, info
    Confidence  float64 `json:"confidence"`  // 0.0–1.0, how confident the LLM is
    Suggestion  string  `json:"suggestion"`  // Recommended mitigation
}
```

### Design Decisions

- **`confidence` field:** Static rules always have confidence 1.0 (deterministic). Agentic findings may be uncertain, so a confidence score lets consumers prioritize.
- **`model_used` field:** Tracks which LLM was used, useful for debugging and reproducibility.
- **`source_key`:** The Python worker downloads the source archive from S3 instead of receiving raw code, keeping the message small.

### Files to Create

| File | Purpose |
|------|---------|
| `internal/model/http/agentic_analysis_dtos.go` | Request, result, and finding DTOs for agentic analysis |

### Testing

- Verify the file compiles: `go build ./internal/model/http/...`
- No runtime tests needed for DTOs alone.
