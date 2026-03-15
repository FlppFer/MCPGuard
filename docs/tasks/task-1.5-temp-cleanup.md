# Task 1.5: Temp Directory Cleanup

| Field | Value |
|-------|-------|
| **ID** | task-1.5 |
| **Phase** | 1 — Server Hardening & Code Quality |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

`utils.DownloadRepo()` clones repositories into OS temp directories and creates zip archives. After static analysis completes (or fails), neither the cloned directory nor the zip file is cleaned up. Over time, repeated analyses will exhaust disk space.

### Expected Behavior

1. After the source archive is uploaded to object storage, the local zip file is deleted.
2. After static analysis completes (success or failure), the cloned repo directory is deleted.
3. Cleanup happens in a `defer` to ensure it runs even on errors.
4. Cleanup failures are logged but do not fail the analysis.

### Acceptance Criteria

- No orphaned temp directories remain after analysis completes.
- Cleanup errors are logged at warn level (non-fatal).
- Analysis functionality is unchanged.

---

## Technical Specification

### Current State

**`internal/service/git_webhook_service.go` (lines 69–132):**

```go
// Download repo — creates temp dir + zip
repo, err := utils.DownloadRepo(repoURL, branch, commit)
// ... uses repo.LocalPath and repo.ZipPath ...

// Goroutine runs analysis but NEVER cleans up repo.LocalPath or repo.ZipPath
go func() {
    // ... analysis ...
    entity.Status = "static_done"
    uc.dbRepo.Update(context.Background(), entity)
    // ← No cleanup of temp files
}()
```

**`internal/model/services/repo_download_result.go`** — `RepoDownloadResultDTO` has `LocalPath` and `ZipPath` fields.

### Changes Required

#### 1. Add cleanup in `git_webhook_service.go`

After uploading the zip to S3 (line 82), delete the zip file:

```go
// After successful S3 upload
if err := os.Remove(repo.ZipPath); err != nil {
    slog.Warn("Failed to clean up zip file", "path", repo.ZipPath, "error", err)
}
```

At the start of the goroutine, add a defer for the cloned repo directory:

```go
go func() {
    // Clean up cloned repo when done (success or failure)
    defer func() {
        if err := os.RemoveAll(repo.LocalPath); err != nil {
            slog.Warn("Failed to clean up cloned repo", "path", repo.LocalPath, "error", err)
        }
    }()

    asyncCtx := context.Background()
    result, err := uc.staticAnalyzer.RunAnalysis(asyncCtx, analysisID, parsedFiles)
    // ... rest of goroutine ...
}()
```

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/git_webhook_service.go` | Add zip removal after upload; add `defer os.RemoveAll` in goroutine |

### Testing

- Trigger an analysis, then check `os.TempDir()` for orphaned MCPGuard directories.
- Trigger a failing analysis (e.g., invalid repo URL), verify temp dirs are still cleaned up.
