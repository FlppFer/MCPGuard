# Test Plan: API Flows & Outcomes

> Based on `docs/specs/api-flows-and-outcomes.md` — covers all 10 flows, authentication, and error paths.
> Tests are organized by layer: unit (controller + service mocks), integration (full stack with mock DB/storage), and the existing auth middleware tests.

---

## Test Inventory Summary

| Flow | Spec Section | Happy Paths | Sad Paths | Total Cases | Existing Tests |
|------|-------------|-------------|-----------|-------------|----------------|
| Auth — API Key | §3.1 | 1 | 4 | 5 | 4 (`auth_test.go`) |
| Auth — Webhook HMAC | §3.2 | 1 | 3 | 4 | 5 (`auth_test.go`) |
| Flow 1 — Manual Analysis | §4 | 1 | 6 | 7 | 0 |
| Flow 2 — Push Webhook | §5 | 1 | 4 | 5 | 0 |
| Flow 3 — PR Webhook | §6 | 1 | 4 | 5 | 0 |
| Flow 4 — Query Status | §7 | 2 | 3 | 5 | 3 (`git_webhook_controller_test.go`) |
| Flow 5 — Static Result | §8 | 1 | 4 | 5 | 4 (`git_webhook_controller_test.go`) |
| Flow 6 — Merged Result | §9 | 2 | 4 | 6 | 0 |
| Flow 7 — Agentic Callback | §10 | 1 | 5 | 6 | 0 |
| Flow 8 — Agentic Result | §11 | 1 | 4 | 5 | 0 |
| Flow 9 — Queue Pipeline | §12 | 1 | 4 | 5 | 0 (noop_publisher_test exists) |
| Flow 10 — PR Comment | §13 | 1 | 3 | 4 | 1 (`markdown_formatter_test.go`) |
| **Totals** | | | | **62** | **17** |

**Gap: 45 new test cases needed.**

---

## Test Strategy

### Layer 1: Controller Unit Tests (httptest + mock services)

Each controller handler is tested in isolation using `httptest.NewRecorder`, `httptest.NewRequest`, and mock service implementations. This is the pattern already established in `git_webhook_controller_test.go`.

**What we test:**
- Request parsing (valid JSON, malformed JSON, missing fields)
- HTTP status codes for each scenario
- Response body structure (error codes, messages, field presence)
- Correct service method invocation
- Error mapping (sentinel errors → HTTP status codes)

### Layer 2: Service Unit Tests (mock DB + mock storage)

Each service method is tested with mock `DatabaseClient` and `StorageRepository` implementations.

**What we test:**
- Correct status transitions persisted to DB
- S3 key patterns used for upload/download
- Error propagation from dependencies
- Sentinel error wrapping

### Layer 3: Integration Tests (optional, future)

Full stack test with real SQLite (in-memory) and local filesystem storage. Verifies the entire pipeline end-to-end. These are more expensive and can be added later.

---

## Test File Layout

```
internal/
├── controller/
│   ├── git_webhook_controller_test.go       ← extend (Flows 1-6)
│   └── agentic_analysis_controller_test.go  ← new (Flows 7-8)
├── service/
│   ├── git_webhook_service_test.go          ← new (Flows 1-6, 9-10)
│   └── agentic_analysis_service_test.go     ← new (Flow 7)
└── middleware/auth/
    └── auth_test.go                         ← already covers §3.1 & §3.2
```

---

## Detailed Test Cases

### A. Flow 1 — Manual Analysis (`POST /v1/analysis`)

**File:** `internal/controller/git_webhook_controller_test.go`

| # | Test Name | Input | Expected | Status | Error Code |
|---|-----------|-------|----------|--------|------------|
| A1 | `TestStartAnalysis_HappyPath` | `{"repo_url":"https://github.com/o/r.git","branch":"main"}` | 202, `analysis_id` present, `status` present, `message` = "Analysis started successfully" | 202 | — |
| A2 | `TestStartAnalysis_MissingRepoURL` | `{"branch":"main"}` | 400 | 400 | `missing_field` |
| A3 | `TestStartAnalysis_MalformedJSON` | `{not json` | 400 | 400 | `invalid_request` |
| A4 | `TestStartAnalysis_DefaultBranch` | `{"repo_url":"..."}` (no branch) | Service called with `branch="main"` | 202 | — |
| A5 | `TestStartAnalysis_ServiceError` | Service returns `error` | 500 | 500 | `analysis_failed` |
| A6 | `TestStartAnalysis_EmptyBody` | empty body | 400 | 400 | `invalid_request` |

**File:** `internal/service/git_webhook_service_test.go`

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| A7 | `TestRequestAnalysis_CreatesEntity` | Valid params | Entity created in DB with `status=created` |
| A8 | `TestRequestAnalysis_CloneFails` | `DownloadRepo` errors | Entity status → `failed`, error returned |
| A9 | `TestRequestAnalysis_UploadFails` | S3 upload errors | Entity status → `failed`, error returned |
| A10 | `TestRequestAnalysis_QueueMode_PublishFails` | Queue enabled, publish fails | Entity status → `failed` |
| A11 | `TestRequestAnalysis_QueueMode_PublishSucceeds` | Queue enabled, publish OK | Entity status → `queued` |

---

### B. Flow 2 — Push Webhook (`POST /v1/webhook/github` with `X-GitHub-Event: push`)

**File:** `internal/controller/git_webhook_controller_test.go`

| # | Test Name | Input | Expected |
|---|-----------|-------|----------|
| B1 | `TestHandleGitHubWebhook_Push_HappyPath` | Valid push payload + event context | 202, `analysis_id` present |
| B2 | `TestHandleGitHubWebhook_Push_MalformedJSON` | Invalid JSON + event=push | 400, `invalid_payload` |
| B3 | `TestHandleGitHubWebhook_Push_MissingCloneURL` | Push payload with empty `clone_url` | 400, `missing_field` |
| B4 | `TestHandleGitHubWebhook_Push_ServiceError` | Service returns error | 500, `analysis_failed` |

**Setup notes:**
- The webhook middleware already reads the body and stores it in context. In controller tests, we need to set the `X-GitHub-Event` context value via `authMiddleware.GitHubEventContextKey`.
- The controller reads the body from `r.Body` (not context payload). So the test body must be the raw JSON payload.

---

### C. Flow 3 — PR Webhook (`POST /v1/webhook/github` with `X-GitHub-Event: pull_request`)

**File:** `internal/controller/git_webhook_controller_test.go`

| # | Test Name | Input | Expected |
|---|-----------|-------|----------|
| C1 | `TestHandleGitHubWebhook_PR_Opened` | PR payload, action=opened | 202, calls `RequestAnalysisWithPR` |
| C2 | `TestHandleGitHubWebhook_PR_Synchronize` | PR payload, action=synchronize | 202 |
| C3 | `TestHandleGitHubWebhook_PR_Closed` | PR payload, action=closed | 200, `{"status":"ignored"}` |
| C4 | `TestHandleGitHubWebhook_PR_MissingCloneURL` | PR payload, empty clone_url | 400, `missing_field` |
| C5 | `TestHandleGitHubWebhook_PR_MalformedJSON` | Invalid JSON + event=pull_request | 400, `invalid_payload` |

---

### D. Flow 4 — Query Status (`GET /v1/analysis/{id}/status`)

**File:** `internal/controller/git_webhook_controller_test.go` — **Already has 3 tests**, need:

| # | Test Name | Input | Expected | Status |
|---|-----------|-------|----------|--------|
| D1 | ✅ `TestGetAnalysisStatus` (success) | Valid ID | 200, status DTO | Exists |
| D2 | ✅ `TestGetAnalysisStatus` (not found) | Unknown ID | 404, `not_found` | Exists |
| D3 | ✅ `TestGetAnalysisStatus_MissingID` | No `{id}` param | 400, `missing_id` | Exists |
| D4 | `TestGetAnalysisStatus_InternalError` | Service returns generic error | 500, `internal_error` | **New** |

---

### E. Flow 5 — Static Result (`GET /v1/analysis/{id}/result`)

**File:** `internal/controller/git_webhook_controller_test.go` — **Already has 4 tests**, need:

| # | Test Name | Input | Expected | Status |
|---|-----------|-------|----------|--------|
| E1 | ✅ `TestGetAnalysisResult` (success) | Valid ID, done | 200, result JSON | Exists |
| E2 | ✅ `TestGetAnalysisResult` (pending) | ID, still running | 202, `analysis_pending` | Exists |
| E3 | ✅ `TestGetAnalysisResult` (not found) | Unknown ID | 404, `not_found` | Exists |
| E4 | ✅ `TestGetAnalysisResult` (download fail) | S3 error | 500, `internal_error` | Exists |
| E5 | ✅ `TestGetAnalysisResult_MissingID` | No `{id}` | 400, `missing_id` | Exists |

**Flow 5 is fully covered!**

---

### F. Flow 6 — Merged Result (`GET /v1/analysis/{id}/result/full`)

**File:** `internal/controller/git_webhook_controller_test.go`

| # | Test Name | Input | Expected |
|---|-----------|-------|----------|
| F1 | `TestGetMergedResult_BothResults` | ID with completed status, both static + agentic | 200, both fields populated |
| F2 | `TestGetMergedResult_StaticOnly` | ID with static_done, no agentic | 200, `agentic_result: null` |
| F3 | `TestGetMergedResult_NotFound` | Unknown ID | 404, `not_found` |
| F4 | `TestGetMergedResult_Pending` | ID still running | 202, `analysis_pending` |
| F5 | `TestGetMergedResult_MissingID` | No `{id}` | 400, `missing_id` |
| F6 | `TestGetMergedResult_InternalError` | Generic service error | 500, `internal_error` |

---

### G. Flow 7 — Agentic Callback (`POST /v1/agentic_analysis`)

**File:** `internal/controller/agentic_analysis_controller_test.go` (new)

| # | Test Name | Input | Expected |
|---|-----------|-------|----------|
| G1 | `TestReceiveAgenticResult_HappyPath` | Valid `AgenticAnalysisResultDTO` | 200, `{"status":"received"}` |
| G2 | `TestReceiveAgenticResult_MalformedJSON` | Bad JSON | 400, `invalid_request` |
| G3 | `TestReceiveAgenticResult_MissingAnalysisID` | DTO with `analysis_id: ""` | 400, `missing_field` |
| G4 | `TestReceiveAgenticResult_NotFound` | Service returns `ErrAnalysisNotFound` | 404, `not_found` |
| G5 | `TestReceiveAgenticResult_UploadFails` | Service returns S3/DB error | 500, `processing_failed` |

**File:** `internal/service/agentic_analysis_service_test.go` (new)

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| G6 | `TestReceiveResult_UploadsToS3` | Valid result | S3 called with key `analysis-results/{id}_agentic.json` |
| G7 | `TestReceiveResult_UpdatesDBStatus` | Valid result | Entity status → `completed` |
| G8 | `TestReceiveResult_S3UploadFails` | S3 error | Error returned, DB not updated |
| G9 | `TestReceiveResult_DBFindFails` | Entity not in DB | `ErrAnalysisNotFound` returned |

---

### H. Flow 8 — Agentic Result (`GET /v1/agentic_analysis/{id}/result`)

**File:** `internal/controller/agentic_analysis_controller_test.go`

| # | Test Name | Input | Expected |
|---|-----------|-------|----------|
| H1 | `TestGetAgenticResult_HappyPath` | ID with completed status | 200, raw JSON |
| H2 | `TestGetAgenticResult_MissingID` | No `{id}` | 400, `missing_id` |
| H3 | `TestGetAgenticResult_NotFound` | Unknown ID | 404, `not_found` |
| H4 | `TestGetAgenticResult_Pending` | Analysis not complete | 202, `analysis_pending` |
| H5 | `TestGetAgenticResult_DownloadFails` | S3 error | 500, `internal_error` |

**File:** `internal/service/agentic_analysis_service_test.go`

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| H6 | `TestGetResult_Success` | Entity completed, S3 returns data | Data returned |
| H7 | `TestGetResult_NotComplete` | Entity in `static_analysis_done` | `ErrAnalysisNotComplete` |
| H8 | `TestGetResult_NotFound` | Entity not in DB | `ErrAnalysisNotFound` |
| H9 | `TestGetResult_S3Error` | Entity complete, S3 fails | Error with "failed to download" |

---

### I. Flow 9 — Queue Pipeline

**File:** `internal/service/git_webhook_service_test.go`

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| I1 | `TestPublishAnalysisJob_Success` | Publisher returns nil | Entity status → `queued`, counter incremented |
| I2 | `TestPublishAnalysisJob_Failure` | Publisher returns error | Entity status → `failed`, error returned |
| I3 | `TestRequestAnalysis_QueueEnabled_PublishesMessage` | Queue enabled | `publisher.Publish` called with correct queue + payload |
| I4 | `TestRequestAnalysis_QueueDisabled_RunsLocally` | Queue disabled | Goroutine runs, no publisher call |

**File:** `internal/messaging/noop_publisher_test.go` — ✅ Already exists

---

### J. Flow 10 — PR Comment Integration

**File:** `internal/service/git_webhook_service_test.go`

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| J1 | `TestLocalAnalysis_PostsPRComment` | Entity has `PRNumber > 0`, analysis succeeds | `prCommentService.PostFindings` called |
| J2 | `TestLocalAnalysis_NoPRNumber_SkipsComment` | Entity `PRNumber = 0` | `PostFindings` NOT called |
| J3 | `TestLocalAnalysis_CommentFails_NonFatal` | `PostFindings` returns error | Analysis still completes (`static_analysis_done`) |

**File:** `internal/service/github_integration/markdown_formatter_test.go` — ✅ Already exists (covers Markdown formatting)

---

### K. Webhook Event Routing

**File:** `internal/controller/git_webhook_controller_test.go`

| # | Test Name | Event Header | Expected |
|---|-----------|-------------|----------|
| K1 | `TestHandleGitHubWebhook_UnknownEvent` | `X-GitHub-Event: issues` | 200, `{"status":"ignored","message":"Event type 'issues' not handled"}` |
| K2 | `TestHandleGitHubWebhook_EmptyEvent` | No event in context | 200, `{"status":"ignored","message":"Event type '' not handled"}` |

---

### L. Agentic Service — SubmitForAnalysis

**File:** `internal/service/agentic_analysis_service_test.go`

| # | Test Name | Scenario | Expected |
|---|-----------|----------|----------|
| L1 | `TestSubmitForAnalysis_Disabled` | `enabled: false` | Returns nil immediately, no HTTP call |
| L2 | `TestSubmitForAnalysis_WorkerReturns200` | Mock server returns 200 | Returns nil |
| L3 | `TestSubmitForAnalysis_WorkerReturns500` | Mock server returns 500 | Returns error with "status 500" |
| L4 | `TestSubmitForAnalysis_WorkerUnreachable` | Bad URL | Returns error with "failed to submit" |

---

## Implementation Order

| Priority | Action | Tests Added |
|----------|--------|-------------|
| 1 | Extend `git_webhook_controller_test.go` — add Flow 1/2/3/6 + event routing tests | ~18 cases |
| 2 | Create `agentic_analysis_controller_test.go` — Flows 7 & 8 | ~10 cases |
| 3 | Create `agentic_analysis_service_test.go` — service layer for agentic | ~8 cases |
| 4 | Create `git_webhook_service_test.go` — queue pipeline, PR comments, core flow | ~9 cases |
| **Total** | | **~45 new test cases** |

---

## Mock Dependencies Needed

### For Controller Tests (already patterned in `git_webhook_controller_test.go`)

```go
// Already exists:
type mockGitWebhookService struct { ... }

// Needed for agentic controller tests:
type mockAgenticAnalysisService struct {
    receiveResultFunc func(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error
    getResultFunc     func(ctx context.Context, analysisID string) ([]byte, error)
    submitFunc        func(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error
}
```

### For Service Tests (new)

```go
// Mock DB client
type mockDatabaseClient struct {
    createFunc  func(ctx context.Context, a *repositories.AnalysisEntity) error
    updateFunc  func(ctx context.Context, a *repositories.AnalysisEntity) error
    findByIDFunc func(ctx context.Context, id string) (*repositories.AnalysisEntity, error)
}

// Mock storage repository
type mockStorageRepository struct {
    uploadFunc   func(ctx context.Context, key, path string) error
    downloadFunc func(ctx context.Context, key string) ([]byte, error)
    getURLFunc   func(key string) (string, error)
}

// Mock static analysis service
type mockStaticAnalyzer struct {
    runFunc func(ctx context.Context, id string, files map[string][]byte) (*model.AnalysisResult, error)
}

// Mock message publisher
type mockPublisher struct {
    publishFunc func(ctx context.Context, queue string, msg []byte) error
    closeFunc   func() error
}

// Mock PR comment service
type mockPRCommentService struct {
    postFunc func(ctx context.Context, repo string, pr int, result *model.AnalysisResult) error
}
```

---

## Run Command

```bash
# Run all tests
go test ./... -v -count=1

# Run only controller tests
go test ./internal/controller/... -v -count=1

# Run only service tests
go test ./internal/service/... -v -count=1

# Run with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```
