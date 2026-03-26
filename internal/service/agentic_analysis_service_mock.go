package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	repositories2 "github.com/FlppFer/MCPGuard/internal/model/repositories"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
)

// mockAgenticAnalysisService simulates the Python agentic worker locally.
// On SubmitForAnalysis it generates mock findings and immediately persists them,
// simulating the full round-trip without an external worker.
type mockAgenticAnalysisService struct {
	dbRepo      db.DatabaseClient
	storageRepo obj_storage.StorageRepository
}

// NewMockAgenticAnalysisService creates a mock agentic service for local development.
func NewMockAgenticAnalysisService(
	dbRepo db.DatabaseClient,
	storageRepo obj_storage.StorageRepository,
) AgenticAnalysisService {
	return &mockAgenticAnalysisService{
		dbRepo:      dbRepo,
		storageRepo: storageRepo,
	}
}

// SubmitForAnalysis generates mock agentic findings and persists them immediately.
func (s *mockAgenticAnalysisService) SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error {
	slog.Info("Mock agentic worker: generating findings", "analysis_id", req.AnalysisID)

	result := s.generateMockResult(req)

	if err := s.persistResult(ctx, result); err != nil {
		return fmt.Errorf("mock agentic worker failed to persist result: %w", err)
	}

	slog.Info("Mock agentic worker: analysis completed", "analysis_id", req.AnalysisID, "findings", len(result.Findings))
	return nil
}

// ReceiveResult persists agentic analysis results to object storage and updates the DB status.
func (s *mockAgenticAnalysisService) ReceiveResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
	return s.persistResult(ctx, result)
}

// GetResult retrieves stored agentic analysis results from object storage.
func (s *mockAgenticAnalysisService) GetResult(ctx context.Context, analysisID string) ([]byte, error) {
	entity, err := s.dbRepo.FindByID(ctx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	if entity.Status != repositories2.StatusCompleted.String() && entity.Status != repositories2.StatusAgentAnalysisDone.String() {
		return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
	}

	s3Key := fmt.Sprintf(S3KeyAgenticResult, analysisID)
	data, err := s.storageRepo.DownloadFile(ctx, s3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to download agentic result: %w", err)
	}

	return data, nil
}

// generateMockResult creates a realistic set of mock agentic findings.
func (s *mockAgenticAnalysisService) generateMockResult(req *httpmodel.AgenticAnalysisRequestDTO) *httpmodel.AgenticAnalysisResultDTO {
	return &httpmodel.AgenticAnalysisResultDTO{
		AnalysisID: req.AnalysisID,
		Summary:    "Mock agentic analysis completed. Simulated findings generated for local development.",
		ModelUsed:  "mock-local-v1",
		Timestamp:  time.Now(),
		Findings: []httpmodel.AgenticFindingDTO{
			{
				Category:    "tool_poisoning",
				Description: "[MOCK] Detected potential tool poisoning: tool description contains hidden instructions that override the agent's behavior.",
				FilePath:    "server.py",
				StartLine:   42,
				EndLine:     58,
				Severity:    httpmodel.SeverityCritical,
				Confidence:  0.92,
				Suggestion:  "Review tool descriptions for hidden instructions. Ensure descriptions only contain legitimate usage information.",
			},
			{
				Category:    "data_exfiltration",
				Description: "[MOCK] Tool handler sends sensitive context data to an external endpoint disguised as a logging call.",
				FilePath:    "tools/fetch_data.py",
				StartLine:   15,
				EndLine:     23,
				Severity:    httpmodel.SeverityHigh,
				Confidence:  0.85,
				Suggestion:  "Audit all outbound HTTP calls in tool handlers. Restrict network access to approved domains only.",
			},
			{
				Category:    "permission_escalation",
				Description: "[MOCK] Tool requests filesystem write access beyond its declared scope through path traversal in the output directory parameter.",
				FilePath:    "tools/file_manager.py",
				StartLine:   30,
				EndLine:     35,
				Severity:    httpmodel.SeverityMedium,
				Confidence:  0.78,
				Suggestion:  "Validate and sanitize all file paths. Use allowlists for permitted directories.",
			},
			{
				Category:    "prompt_injection",
				Description: "[MOCK] Resource content contains embedded instructions that could manipulate the agent's decision-making when processed.",
				FilePath:    "resources/config_loader.py",
				StartLine:   8,
				EndLine:     12,
				Severity:    httpmodel.SeverityHigh,
				Confidence:  0.88,
				Suggestion:  "Sanitize resource content before passing to LLM context. Implement input validation on all resource handlers.",
			},
		},
	}
}

// persistResult uploads the agentic result to object storage and updates the DB status to completed.
func (s *mockAgenticAnalysisService) persistResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal agentic result: %w", err)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(TmpFileAgenticResult, result.AnalysisID))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	s3Key := fmt.Sprintf(S3KeyAgenticResult, result.AnalysisID)
	if err := s.storageRepo.UploadFile(ctx, s3Key, tmpFile); err != nil {
		return fmt.Errorf("failed to upload agentic result: %w", err)
	}

	slog.Info("Mock agentic results uploaded to storage", "analysis_id", result.AnalysisID, "s3_key", s3Key)

	// Update DB status to reflect agentic analysis completion
	entity, err := s.dbRepo.FindByID(ctx, result.AnalysisID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	entity.Status = repositories2.StatusCompleted.String()
	entity.UpdatedAt = time.Now()
	if err := s.dbRepo.Update(ctx, entity); err != nil {
		return fmt.Errorf("failed to update analysis status: %w", err)
	}

	return nil
}
