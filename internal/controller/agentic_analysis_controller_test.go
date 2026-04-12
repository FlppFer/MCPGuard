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

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service"
)

// mockAgenticService implements service.AgenticAnalysisService for testing.
type mockAgenticService struct {
	submitFunc      func(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error
	receiveFunc     func(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error
	getResultFunc   func(ctx context.Context, analysisID string) ([]byte, error)
}

func (m *mockAgenticService) SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error {
	if m.submitFunc != nil {
		return m.submitFunc(ctx, req)
	}
	return nil
}

func (m *mockAgenticService) ReceiveResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
	if m.receiveFunc != nil {
		return m.receiveFunc(ctx, result)
	}
	return nil
}

func (m *mockAgenticService) GetResult(ctx context.Context, analysisID string) ([]byte, error) {
	if m.getResultFunc != nil {
		return m.getResultFunc(ctx, analysisID)
	}
	return nil, nil
}

// --- Flow G: ReceiveAgenticResult (POST /v1/agentic_analysis) ---

func TestReceiveAgenticResult(t *testing.T) {
	validPayload := httpmodel.AgenticAnalysisResultDTO{
		AnalysisID: "analysis-abc",
		Summary:    "Found 2 issues",
		Findings: []httpmodel.AgenticFindingDTO{
			{
				Category:    "tool_poisoning",
				Description: "Dangerous eval usage",
				FilePath:    "main.py",
				Severity:    httpmodel.SeverityHigh,
				Confidence:  httpmodel.ConfidenceFull,
			},
		},
		Timestamp: time.Now(),
	}

	tests := []struct {
		name           string
		body           string
		mockFunc       func(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:           "G1 - happy path",
			body:           toJSON(t, validPayload),
			mockFunc:       nil,
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"status": "received"},
		},
		{
			name:           "G2 - malformed JSON",
			body:           `{bad json`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeInvalidRequest},
		},
		{
			name:           "G3 - missing analysis_id",
			body:           `{"analysis_id":"","summary":"ok","findings":[]}`,
			mockFunc:       nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": ErrCodeMissingField},
		},
		{
			name: "G4 - analysis not found",
			body: toJSON(t, validPayload),
			mockFunc: func(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
				return fmt.Errorf("%w: record not found", service.ErrAnalysisNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   map[string]interface{}{"error": ErrCodeNotFound},
		},
		{
			name: "G5 - storage/DB error",
			body: toJSON(t, validPayload),
			mockFunc: func(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
				return fmt.Errorf("s3 upload failed: connection refused")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeProcessingFailed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAgenticService{receiveFunc: tt.mockFunc}
			ctrl := NewAgenticAnalysisController(svc)

			req := httptest.NewRequest(http.MethodPost, "/v1/agentic_analysis", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			ctrl.ReceiveAgenticResult().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}

// --- Flow H: GetAgenticResult (GET /v1/agentic_analysis/{id}/result) ---

func TestGetAgenticResult(t *testing.T) {
	storedResult := httpmodel.AgenticAnalysisResultDTO{
		AnalysisID: "analysis-xyz",
		Summary:    "1 critical finding",
		Findings:   []httpmodel.AgenticFindingDTO{},
		Timestamp:  time.Now(),
	}
	storedBytes, _ := json.Marshal(storedResult)

	tests := []struct {
		name           string
		analysisID     string
		mockFunc       func(ctx context.Context, analysisID string) ([]byte, error)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:       "H1 - happy path returns agentic result",
			analysisID: "analysis-xyz",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return storedBytes, nil
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"analysis_id": "analysis-xyz"},
		},
		{
			name:       "H2 - analysis not found",
			analysisID: "missing-id",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("%w: record not found", service.ErrAnalysisNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   map[string]interface{}{"error": ErrCodeNotFound},
		},
		{
			name:       "H3 - analysis not complete yet",
			analysisID: "pending-id",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("%w, current status: static_done", service.ErrAnalysisNotComplete)
			},
			expectedStatus: http.StatusAccepted,
			expectedBody:   map[string]interface{}{"error": ErrCodeAnalysisPending},
		},
		{
			name:       "H4 - internal storage error",
			analysisID: "analysis-xyz",
			mockFunc: func(ctx context.Context, analysisID string) ([]byte, error) {
				return nil, fmt.Errorf("failed to download agentic result: s3 error")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": ErrCodeInternalError},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAgenticService{getResultFunc: tt.mockFunc}
			ctrl := NewAgenticAnalysisController(svc)

			req := httptest.NewRequest(http.MethodGet, "/v1/agentic_analysis/"+tt.analysisID+"/result", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.analysisID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			rec := httptest.NewRecorder()

			ctrl.GetAgenticResult().ServeHTTP(rec, req)

			assertStatus(t, tt.expectedStatus, rec.Code)
			assertBodyContains(t, tt.expectedBody, rec.Body.Bytes())
		})
	}
}

// --- helpers ---

func toJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("toJSON: %v", err)
	}
	return string(b)
}

func assertStatus(t *testing.T, expected, got int) {
	t.Helper()
	if expected != got {
		t.Errorf("expected HTTP %d, got %d", expected, got)
	}
}

func assertBodyContains(t *testing.T, expected map[string]interface{}, body []byte) {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response body: %v\nbody: %s", err, body)
	}
	for k, v := range expected {
		if resp[k] != v {
			t.Errorf("body[%q]: expected %v, got %v", k, v, resp[k])
		}
	}
}
