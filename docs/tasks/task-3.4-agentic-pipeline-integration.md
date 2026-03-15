# Task 3.4: Integrate Agentic Submission into Pipeline

| Field | Value |
|-------|-------|
| **ID** | task-3.4 |
| **Phase** | 3 — Agentic Analysis Integration |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-3.2, task-3.3 |

---

## Functional Specification

### Problem Statement

After static analysis completes, the pipeline stops at `static_done`. The MCPGuard article describes a two-phase analysis: static rules followed by AI-based semantic analysis. The pipeline should optionally trigger agentic analysis after static analysis succeeds.

### Expected Behavior

1. After static analysis completes successfully, if agentic analysis is **enabled** in config:
   - Update status to `waiting_agent_analysis`.
   - Submit a job to the Python agentic worker with the analysis ID and source S3 key.
   - If submission fails, log a warning but don't fail the overall analysis; keep status at `static_analysis_done`.
2. If agentic analysis is **disabled**, the pipeline ends at `static_analysis_done` (or `completed`).
3. The overall analysis reaches `completed` only after both static and agentic phases finish.

### Acceptance Criteria

- With `agentic.enabled: true`, pipeline transitions: `static_done` → `waiting_agent_analysis`.
- With `agentic.enabled: false`, pipeline stays at `static_analysis_done`.
- Agentic submission failure does not crash the pipeline.
- Status `completed` is set only after the agentic callback endpoint receives results (handled by task-3.3).

---

## Technical Specification

### Current State

**`internal/service/git_webhook_service.go` (goroutine, line 106–132):**
```go
go func() {
    asyncCtx := context.Background()
    result, err := uc.staticAnalyzer.RunAnalysis(asyncCtx, analysisID, parsedFiles)
    if err != nil {
        // ... error handling ...
        return
    }
    if err := uc.uploadAnalysisResult(asyncCtx, analysisID, result); err != nil {
        // ... error handling ...
        return
    }
    entity.Status = "static_done"
    entity.UpdatedAt = time.Now()
    uc.dbRepo.Update(context.Background(), entity)
    // ← Pipeline ends here
}()
```

### Changes Required

#### 1. Add agentic service to `gitWebhookServiceImpl`

```go
type gitWebhookServiceImpl struct {
    dbRepo          db.DatabaseClient
    storageRepo     obj_storage.StorageRepository
    staticAnalyzer  static_analysis.Service
    agenticService  AgenticAnalysisService  // NEW
    agenticEnabled  bool                     // NEW
}
```

Update `NewGitWebhookService` constructor to accept these new params.

#### 2. Add agentic submission after static analysis

At the end of the goroutine, after `entity.Status = "static_done"`:

```go
entity.Status = "static_analysis_done"
entity.UpdatedAt = time.Now()
uc.dbRepo.Update(context.Background(), entity)

// Optionally trigger agentic analysis
if uc.agenticEnabled {
    entity.Status = "waiting_agent_analysis"
    entity.UpdatedAt = time.Now()
    uc.dbRepo.Update(context.Background(), entity)

    agenticReq := &httpmodel.AgenticAnalysisRequestDTO{
        AnalysisID: analysisID,
        RepoURL:    repoURL,
        Branch:     branch,
        Commit:     commit,
        SourceKey:  fmt.Sprintf("%s.zip", analysisID),
    }
    if err := uc.agenticService.SubmitForAnalysis(asyncCtx, agenticReq); err != nil {
        slog.Warn("Failed to submit agentic analysis, continuing without it",
            "analysis_id", analysisID, "error", err)
        // Revert to static_done since agentic couldn't start
        entity.Status = "static_analysis_done"
        entity.UpdatedAt = time.Now()
        uc.dbRepo.Update(context.Background(), entity)
    }
}
```

#### 3. Update `ReceiveResult` in agentic service to set final status

When the Python worker calls back with results, `ReceiveResult` should:
- Upload findings to S3.
- Update status to `agent_analysis_done`.
- If no further phases remain, set status to `completed`.

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/git_webhook_service.go` | Add agentic service field, add submission after static phase |
| `cmd/api/setup/resources.go` | Pass agentic service + config to `NewGitWebhookService` |

### Testing

- With `enabled: true` and mock agentic service → verify status transitions through `waiting_agent_analysis`.
- With `enabled: false` → verify pipeline ends at `static_analysis_done`.
- With `enabled: true` and failing worker → verify fallback to `static_analysis_done`.
