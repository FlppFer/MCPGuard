# Task 6.3: Extract PR Number from Webhook Payload

| Field | Value |
|-------|-------|
| **ID** | task-6.3 |
| **Phase** | 6 — GitHub Actions PR Integration |
| **Priority** | Medium |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-6.1 (PR Comment Service) |

---

## Functional Specification

### Problem Statement

The current webhook handler only processes GitHub `push` events (`GitHubPushPayload`). For PR commenting to work, the API also needs to handle `pull_request` events to extract the PR number and repository full name. Without this metadata, the PR Comment Service (task-6.1) has no target to post comments to.

### Expected Behavior

1. The webhook endpoint detects the event type from the `X-GitHub-Event` header.
2. For `push` events, existing behavior is preserved.
3. For `pull_request` events (actions: `opened`, `synchronize`, `reopened`):
   - The PR number and repo full name are extracted.
   - These are stored on the `AnalysisEntity` for later use by the PR Comment Service.
   - Analysis is triggered using the PR's head branch and SHA.
4. After analysis completes, if the entity has a PR number, the PR Comment Service posts findings.

### Acceptance Criteria

- `pull_request` events with action `opened` or `synchronize` trigger analysis.
- PR number and repo full name are persisted on the analysis entity.
- After analysis, a comment is posted to the correct PR (if GitHub integration is enabled).
- `push` events continue to work unchanged.
- Other `pull_request` actions (e.g., `closed`, `labeled`) are ignored.

---

## Technical Specification

### Current State

**`internal/model/http/git_webhook_request.go`:**
Only `GitHubPushPayload` exists. No PR payload.

**`internal/controller/git_webhook_controller.go` (line 71–110):**
`HandleGitHubWebhook()` always decodes as `GitHubPushPayload`. Does not check `X-GitHub-Event` header.

**`internal/model/repositories/analysis_entity.go`:**
No `PRNumber` or `RepoFullName` fields.

### Changes Required

#### 1. Add `GitHubPullRequestPayload` DTO

In `internal/model/http/git_webhook_request.go`:

```go
// GitHubPullRequestPayload represents the GitHub pull_request event webhook payload.
type GitHubPullRequestPayload struct {
    Action      string `json:"action"` // "opened", "synchronize", "reopened", "closed", etc.
    Number      int    `json:"number"` // PR number
    PullRequest struct {
        Head struct {
            Ref string `json:"ref"` // branch name
            SHA string `json:"sha"` // commit SHA
        } `json:"head"`
    } `json:"pull_request"`
    Repository struct {
        CloneURL string `json:"clone_url"`
        FullName string `json:"full_name"` // "owner/repo"
    } `json:"repository"`
}
```

#### 2. Add fields to `AnalysisEntity`

In `internal/model/repositories/analysis_entity.go`:

```go
type AnalysisEntity struct {
    // ... existing fields ...
    PRNumber     int    `gorm:"column:pr_number"`      // 0 if not a PR-triggered analysis
    RepoFullName string `gorm:"type:text;column:repo_full_name"` // "owner/repo"
}
```

#### 3. Update webhook controller

In `HandleGitHubWebhook()`, check `X-GitHub-Event` header (already stored in context by `WebhookAuth` middleware as `GitHubEventContextKey`):

```go
func (c *gitWebhookController) HandleGitHubWebhook() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        event := middleware.GetGitHubEventFromContext(r.Context())

        switch event {
        case "push":
            c.handlePushEvent(w, r)
        case "pull_request":
            c.handlePullRequestEvent(w, r)
        default:
            c.writeError(w, http.StatusOK, "ignored", fmt.Sprintf("Event type '%s' not handled", event))
        }
    }
}

func (c *gitWebhookController) handlePullRequestEvent(w http.ResponseWriter, r *http.Request) {
    var payload httpmodel.GitHubPullRequestPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        c.writeError(w, http.StatusBadRequest, "invalid_payload", "Failed to parse PR payload")
        return
    }

    // Only process actionable PR events
    switch payload.Action {
    case "opened", "synchronize", "reopened":
        // proceed
    default:
        c.writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "action": payload.Action})
        return
    }

    repoURL := payload.Repository.CloneURL
    branch := payload.PullRequest.Head.Ref
    commit := payload.PullRequest.Head.SHA

    // Pass PR metadata to service layer
    result, err := c.gitWebhookService.RequestAnalysisWithPR(r.Context(),
        repoURL, branch, commit, payload.Number, payload.Repository.FullName)
    // ...
}
```

#### 4. Update service layer

Add `RequestAnalysisWithPR` method (or add optional params to `RequestAnalysis`) that sets `PRNumber` and `RepoFullName` on the entity.

#### 5. Post PR comment after analysis

In the analysis goroutine, after results are uploaded:

```go
if entity.PRNumber > 0 && uc.prCommentService != nil {
    if err := uc.prCommentService.PostFindings(asyncCtx, entity.RepoFullName, entity.PRNumber, result); err != nil {
        slog.Warn("Failed to post PR comment", "analysis_id", analysisID, "error", err)
    }
}
```

### Files to Modify

| File | Change |
|------|--------|
| `internal/model/http/git_webhook_request.go` | Add `GitHubPullRequestPayload` |
| `internal/model/repositories/analysis_entity.go` | Add `PRNumber`, `RepoFullName` fields |
| `internal/controller/git_webhook_controller.go` | Route by event type, add PR handler |
| `internal/service/git_webhook_service.go` | Add PR metadata to entity, call PR comment service |

### Testing

- Send mock `pull_request` webhook with action `opened` → analysis starts, entity has PR number.
- Send mock `pull_request` webhook with action `closed` → 200 OK, no analysis triggered.
- Send mock `push` webhook → existing behavior unchanged.
- After PR analysis completes → PR comment service is called with correct repo/PR number.
