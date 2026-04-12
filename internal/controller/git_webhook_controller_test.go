package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	authMiddleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service"
)

// mockGitWebhookService implements service.GitWebhookService for testing
type mockGitWebhookService struct {
	requestAnalysisFunc   func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
	getAnalysisStatusFunc func(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error)
	getAnalysisResultFunc func(ctx context.Context, analysisID string) ([]byte, error)
	getMergedResultFunc   func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error)
}

func (m *mockGitWebhookService) RequestAnalysis(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
	if m.requestAnalysisFunc != nil {
		return m.requestAnalysisFunc(ctx, repoURL, branch, commit)
	}
	return nil, nil
}

func (m *mockGitWebhookService) RequestAnalysisWithPR(ctx context.Context, repoURL, branch, commit string, prNumber int, repoFullName string) (*services.GitWebhookAnalysisResultDTO, error) {
	if m.requestAnalysisFunc != nil {
		return m.requestAnalysisFunc(ctx, repoURL, branch, commit)
	}
	return nil, nil
}

func (m *mockGitWebhookService) GetAnalysisStatus(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error) {
	if m.getAnalysisStatusFunc != nil {
		return m.getAnalysisStatusFunc(ctx, analysisID)
	}
	return nil, nil
}

func (m *mockGitWebhookService) GetAnalysisResult(ctx context.Context, analysisID string) ([]byte, error) {
	if m.getAnalysisResultFunc != nil {
		return m.getAnalysisResultFunc(ctx, analysisID)
	}
	return nil, nil
}

func (m *mockGitWebhookService) GetMergedResult(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
	if m.getMergedResultFunc != nil {
		return m.getMergedResultFunc(ctx, analysisID)
	}
	return nil, nil
}

func TestGetAnalysisStatus(t *testing.T) {
	tests := []struct {
		name           string
		analysisID     string
		mockFunc       func(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:       "success - returns analysis status",
			analysisID: "test-analysis-123",
			mockFunc: func(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error) {
				return &services.AnalysisStatusDTO{
					AnalysisID: "test-analysis-123",
					RepoURL:    "https://github.com/test/repo",
					Branch:     "main",
					Status:     "static_done",
					CreatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
					UpdatedAt:  time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC),
				}, nil
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"analysis_id": "test-analysis-123",
				"repo_url":    "https://github.com/test/repo",
				"branch":      "main",
				"status":      "static_done",
			},
		},
		{
			name:       "not found - analysis does not exist",
			analysisID: "nonexistent-id",
			mockFunc: func(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error) {
				return nil, fmt.Errorf("%w: record not found", service.ErrAnalysisNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"error":   "not_found",
				"message": "analysis not found: record not found",
			},
		},
		{
			name:       "success - analysis with error message",
			analysisID: "failed-analysis",
			mockFunc: func(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error) {
				return &services.AnalysisStatusDTO{
					AnalysisID:   "failed-analysis",
					RepoURL:      "https://github.com/test/repo",
					Branch:       "main",
					Status:       "static_analysis_failed",
					ErrorMessage: "parsing error occurred",
					CreatedAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
					UpdatedAt:    time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC),
				}, nil
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"analysis_id":   "failed-analysis",
				"status":        "static_analysis_failed",
				"error_message": "parsing error occurred",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockGitWebhookService{
				getAnalysisStatusFunc: tt.mockFunc,
			}
			controller := NewGitWebhookController(mockService)

			// Create request with chi URL params
			req := httptest.NewRequest(http.MethodGet, "/v1/security_analysis/"+tt.analysisID, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.analysisID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			rec := httptest.NewRecorder()
			controller.GetAnalysisStatus().ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			for key, expectedVal := range tt.expectedBody {
				if response[key] != expectedVal {
					t.Errorf("expected %s=%v, got %v", key, expectedVal, response[key])
				}
			}
		})
	}
}

func TestGetAnalysisResult(t *testing.T) {
	sampleResult := map[string]interface{}{
		"analysis_id":    "test-123",
		"files_analyzed": 5,
		"findings": []map[string]interface{}{
			{
				"rule_id":  "MCP-DTI-002",
				"message":  "Command injection detected",
				"severity": "high",
			},
		},
	}
	sampleResultBytes, _ := json.Marshal(sampleResult)

	tests := []struct {
		name           string
		analysisID     string
		mockFunc       func(ctx context.Context, analysisID string) ([]byte, error)
		expectedStatus int
		checkBody      func(t *testing.T, body []byte)
	}{
		{
			name:       "success - returns analysis result",
			analysisID: "test-123",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return sampleResultBytes, nil
			},
			expectedStatus: http.StatusOK,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to unmarshal result: %v", err)
				}
				if result["analysis_id"] != "test-123" {
					t.Errorf("expected analysis_id=test-123, got %v", result["analysis_id"])
				}
				if result["files_analyzed"].(float64) != 5 {
					t.Errorf("expected files_analyzed=5, got %v", result["files_analyzed"])
				}
			},
		},
		{
			name:       "pending - analysis not complete",
			analysisID: "pending-123",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("%w, current status: static_analysis_started", service.ErrAnalysisNotComplete)
			},
			expectedStatus: http.StatusAccepted,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to unmarshal result: %v", err)
				}
				if result["error"] != "analysis_pending" {
					t.Errorf("expected error=analysis_pending, got %v", result["error"])
				}
			},
		},
		{
			name:       "not found - analysis does not exist",
			analysisID: "nonexistent",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("%w: record not found", service.ErrAnalysisNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to unmarshal result: %v", err)
				}
				if result["error"] != "not_found" {
					t.Errorf("expected error=not_found, got %v", result["error"])
				}
			},
		},
		{
			name:       "internal error - download failed",
			analysisID: "download-fail",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("failed to download result: %w", fmt.Errorf("S3 error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to unmarshal result: %v", err)
				}
				if result["error"] != "internal_error" {
					t.Errorf("expected error=internal_error, got %v", result["error"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockGitWebhookService{
				getAnalysisResultFunc: tt.mockFunc,
			}
			controller := NewGitWebhookController(mockService)

			req := httptest.NewRequest(http.MethodGet, "/v1/security_analysis/"+tt.analysisID+"/result", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.analysisID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			rec := httptest.NewRecorder()
			controller.GetAnalysisResult().ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.Bytes())
			}
		})
	}
}

func TestGetAnalysisStatus_MissingID(t *testing.T) {
	mockService := &mockGitWebhookService{}
	controller := NewGitWebhookController(mockService)

	req := httptest.NewRequest(http.MethodGet, "/v1/security_analysis/", nil)
	// No URL param set - simulates missing ID
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	controller.GetAnalysisStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["error"] != "missing_id" {
		t.Errorf("expected error=missing_id, got %v", response["error"])
	}
}

func TestGetAnalysisResult_MissingID(t *testing.T) {
	mockService := &mockGitWebhookService{}
	controller := NewGitWebhookController(mockService)

	req := httptest.NewRequest(http.MethodGet, "/v1/security_analysis//result", nil)
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	controller.GetAnalysisResult().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["error"] != "missing_id" {
		t.Errorf("expected error=missing_id, got %v", response["error"])
	}
}

// --- Flow A: StartAnalysis (POST /v1/analysis) ---

func TestStartAnalysis(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		mockFunc       func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "A1 - happy path",
			body: `{"repo_url":"https://github.com/test/repo.git","branch":"main"}`,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return &services.GitWebhookAnalysisResultDTO{
					AnalysisID: "new-analysis-id",
					Status:     "static_analysis_running",
				}, nil
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"analysis_id": "new-analysis-id", "status": "static_analysis_running"},
		},
		{
			name:           "A2 - malformed JSON",
			body:           `{bad json`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeInvalidRequest},
		},
		{
			name:           "A3 - missing repo_url",
			body:           `{"branch":"main"}`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeMissingField},
		},
		{
			name: "A4 - service error",
			body: `{"repo_url":"https://github.com/test/repo.git"}`,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return nil, fmt.Errorf("git clone failed: exit status 128")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeAnalysisFailed},
		},
		{
			name: "A5 - defaults branch to main when empty",
			body: `{"repo_url":"https://github.com/test/repo.git"}`,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				if branch != "main" {
					return nil, fmt.Errorf("expected branch=main, got %s", branch)
				}
				return &services.GitWebhookAnalysisResultDTO{AnalysisID: "id-1", Status: "static_analysis_running"}, nil
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"analysis_id": "id-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockGitWebhookService{requestAnalysisFunc: tt.mockFunc}
			ctrl := NewGitWebhookController(svc)

			req := httptest.NewRequest(http.MethodPost, "/v1/analysis", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			ctrl.StartAnalysis().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}

// --- Flow B: Push Webhook (HandleGitHubWebhook with push event) ---

func withGitHubEvent(req *http.Request, event string) *http.Request {
	ctx := authMiddleware.WithGitHubEvent(req.Context(), event)
	return req.WithContext(ctx)
}

func TestHandleGitHubWebhook_Push(t *testing.T) {
	validPush := `{"ref":"refs/heads/main","after":"abc123","before":"000000","repository":{"clone_url":"https://github.com/test/repo.git","full_name":"test/repo"}}`

	tests := []struct {
		name           string
		body           string
		mockFunc       func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "B1 - happy path push",
			body: validPush,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return &services.GitWebhookAnalysisResultDTO{AnalysisID: "push-id", Status: "static_analysis_running"}, nil
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"analysis_id": "push-id"},
		},
		{
			name:           "B2 - malformed push payload",
			body:           `{bad json`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeInvalidPayload},
		},
		{
			name:           "B3 - missing clone_url",
			body:           `{"ref":"refs/heads/main","repository":{"clone_url":"","full_name":"test/repo"}}`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeMissingField},
		},
		{
			name: "B4 - service error",
			body: validPush,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return nil, fmt.Errorf("git clone failed")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeAnalysisFailed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockGitWebhookService{requestAnalysisFunc: tt.mockFunc}
			ctrl := NewGitWebhookController(svc)

			req := httptest.NewRequest(http.MethodPost, "/v1/webhook/github", strings.NewReader(tt.body))
			req = withGitHubEvent(req, "push")
			rec := httptest.NewRecorder()

			ctrl.HandleGitHubWebhook().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}

// --- Flow C: PR Webhook ---

func TestHandleGitHubWebhook_PullRequest(t *testing.T) {
	validPR := `{"action":"opened","number":42,"pull_request":{"head":{"ref":"feature/branch","sha":"deadbeef"}},"repository":{"clone_url":"https://github.com/test/repo.git","full_name":"test/repo"}}`

	tests := []struct {
		name           string
		body           string
		mockFunc       func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "C1 - happy path PR opened",
			body: validPR,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return &services.GitWebhookAnalysisResultDTO{AnalysisID: "pr-id", Status: "static_analysis_running"}, nil
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"analysis_id": "pr-id"},
		},
		{
			name:           "C2 - malformed PR payload",
			body:           `{bad}`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeInvalidPayload},
		},
		{
			name:           "C3 - ignored PR action (closed)",
			body:           `{"action":"closed","number":1,"pull_request":{"head":{"ref":"main","sha":"abc"}},"repository":{"clone_url":"https://github.com/test/repo.git","full_name":"test/repo"}}`,
			mockFunc:       nil,
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"status": "ignored"},
		},
		{
			name: "C4 - service error on PR",
			body: validPR,
			mockFunc: func(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error) {
				return nil, fmt.Errorf("clone failed")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeAnalysisFailed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockGitWebhookService{requestAnalysisFunc: tt.mockFunc}
			ctrl := NewGitWebhookController(svc)

			req := httptest.NewRequest(http.MethodPost, "/v1/webhook/github", strings.NewReader(tt.body))
			req = withGitHubEvent(req, "pull_request")
			rec := httptest.NewRecorder()

			ctrl.HandleGitHubWebhook().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}

// --- Flow E: Unknown/empty webhook event ---

func TestHandleGitHubWebhook_UnknownEvent(t *testing.T) {
	ctrl := NewGitWebhookController(&mockGitWebhookService{})

	for _, event := range []string{"", "ping", "star", "release"} {
		t.Run("event="+event, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/webhook/github", strings.NewReader(`{}`))
			req = withGitHubEvent(req, event)
			rec := httptest.NewRecorder()

			ctrl.HandleGitHubWebhook().ServeHTTP(rec, req)

			assertStatus(t, http.StatusOK, rec.Code)
			assertBodyContains(t, map[string]interface{}{"status": "ignored"}, rec.Body.Bytes())
		})
	}
}

// --- Flow F: GetMergedResult (GET /v1/analysis/{id}/result/full) ---

func TestGetMergedResult(t *testing.T) {
	tests := []struct {
		name           string
		analysisID     string
		mockFunc       func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:       "F1 - happy path returns merged result",
			analysisID: "merged-id",
			mockFunc: func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
				return &services.MergedAnalysisResultDTO{
					AnalysisID: "merged-id",
					Status:     "completed",
				}, nil
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"analysis_id": "merged-id", "status": "completed"},
		},
		{
			name:       "F2 - analysis not found",
			analysisID: "missing",
			mockFunc: func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
				return nil, fmt.Errorf("%w", service.ErrAnalysisNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   map[string]interface{}{"error": ErrCodeNotFound},
		},
		{
			name:       "F3 - analysis not complete yet",
			analysisID: "pending",
			mockFunc: func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
				return nil, fmt.Errorf("%w, current status: static_done", service.ErrAnalysisNotComplete)
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"error": ErrCodeAnalysisPending},
		},
		{
			name:           "F4 - missing ID",
			analysisID:     "",
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeMissingID},
		},
		{
			name:       "F5 - internal error",
			analysisID: "err-id",
			mockFunc: func(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
				return nil, fmt.Errorf("unexpected db error")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeInternalError},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockGitWebhookService{getMergedResultFunc: tt.mockFunc}
			ctrl := NewGitWebhookController(svc)

			req := httptest.NewRequest(http.MethodGet, "/v1/analysis/"+tt.analysisID+"/result/full", nil)
			rctx := chi.NewRouteContext()
			if tt.analysisID != "" {
				rctx.URLParams.Add("id", tt.analysisID)
			}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			rec := httptest.NewRecorder()

			ctrl.GetMergedResult().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}
