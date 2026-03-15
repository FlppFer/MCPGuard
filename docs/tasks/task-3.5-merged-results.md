# Task 3.5: Merged Results Endpoint

| Field | Value |
|-------|-------|
| **ID** | task-3.5 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | Low |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-3.4 |

---

## Functional Specification

### Problem Statement

When both static and agentic analysis are complete, there is no single endpoint to get a combined view of all findings. Consumers must make two separate API calls and merge results themselves.

### Expected Behavior

1. A new endpoint `GET /v1/analysis/{id}/result/full` returns a merged JSON response containing both static and agentic findings.
2. If only static results exist (agentic not run), the response includes static findings with `agentic_findings: null`.
3. The endpoint requires the analysis to be in `completed` or `static_analysis_done` status.

### Acceptance Criteria

- Endpoint returns merged JSON with both `static_findings` and `agentic_findings` arrays.
- Works correctly when only static results exist (agentic is null/empty).
- Returns 404 if analysis doesn't exist.
- Returns 202 if analysis is still in progress.

---

## Technical Specification

### New DTO

```go
// MergedAnalysisResultDTO combines static and agentic analysis findings.
type MergedAnalysisResultDTO struct {
    AnalysisID      string                        `json:"analysis_id"`
    Status          string                        `json:"status"`
    StaticResult    *model.AnalysisResult         `json:"static_result,omitempty"`
    AgenticResult   *httpmodel.AgenticAnalysisResultDTO `json:"agentic_result,omitempty"`
}
```

### New Service Method

Add to `GitWebhookService` interface:

```go
GetMergedResult(ctx context.Context, analysisID string) (*MergedAnalysisResultDTO, error)
```

Implementation:
1. Fetch analysis entity from DB.
2. Download static result from S3 (`{id}_static.json`), deserialize.
3. Download agentic result from S3 (`{id}_agentic.json`), deserialize (may not exist — that's OK).
4. Return merged DTO.

### New Route

```
GET /v1/analysis/{id}/result/full → GitWebhookController.GetMergedResult()
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/model/services/merged_result.go` | `MergedAnalysisResultDTO` |

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/git_webhook_service.go` | Add `GetMergedResult` method |
| `internal/controller/git_webhook_controller.go` | Add handler |
| `cmd/api/setup/routes.go` | Register route |

### Testing

- Analysis with both results → returns merged JSON with both arrays populated.
- Analysis with static only → returns merged JSON with `agentic_result: null`.
- Analysis in progress → returns 202.
