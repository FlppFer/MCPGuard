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

	"github.com/FlppFer/MCPGuard/internal/metrics"
	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	repositories2 "github.com/FlppFer/MCPGuard/internal/model/repositories"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	ghintegration "github.com/FlppFer/MCPGuard/internal/service/github_integration"
)

// AgenticAnalysisService defines the interface for AI-based semantic analysis operations.
type AgenticAnalysisService interface {
	// SubmitForAnalysis sends an analysis job to the Python agentic worker.
	SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error

	// ReceiveResult processes and persists results from the Python worker.
	ReceiveResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error

	// GetResult retrieves stored agentic analysis results for an analysis ID.
	GetResult(ctx context.Context, analysisID string) ([]byte, error)
}

type agenticAnalysisServiceImpl struct {
	dbRepo           db.DatabaseClient
	storageRepo      obj_storage.StorageRepository
	workerURL        string
	httpClient       *http.Client
	enabled          bool
	prCommentService ghintegration.PRCommentService
}

// NewAgenticAnalysisService creates a new agentic analysis service.
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

// WithPRCommentService sets the PR comment service on an existing agentic service instance.
func WithPRCommentService(svc AgenticAnalysisService, prCommentService ghintegration.PRCommentService) AgenticAnalysisService {
	if impl, ok := svc.(*agenticAnalysisServiceImpl); ok {
		impl.prCommentService = prCommentService
	}
	return svc
}

// SubmitForAnalysis sends an analysis job to the Python agentic worker via HTTP POST.
func (s *agenticAnalysisServiceImpl) SubmitForAnalysis(ctx context.Context, req *httpmodel.AgenticAnalysisRequestDTO) error {
	if !s.enabled {
		slog.Debug("Agentic analysis disabled, skipping submission", "analysis_id", req.AnalysisID)
		return nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal agentic request: %w", err)
	}

	url := fmt.Sprintf(WorkerAnalyzePath, s.workerURL)
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

	metrics.AgenticAnalysisSubmitted.Inc()
	slog.Info("Agentic analysis submitted", "analysis_id", req.AnalysisID, "worker_url", url)
	return nil
}

// ReceiveResult persists agentic analysis results to object storage and updates the DB status.
func (s *agenticAnalysisServiceImpl) ReceiveResult(ctx context.Context, result *httpmodel.AgenticAnalysisResultDTO) error {
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

	slog.Info("Agentic results uploaded to storage", "analysis_id", result.AnalysisID, "s3_key", s3Key)

	// Update DB status to reflect agentic analysis completion
	entity, err := s.dbRepo.FindByID(ctx, result.AnalysisID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	agenticDuration := time.Since(entity.UpdatedAt)
	entity.Status = repositories2.StatusCompleted.String()
	entity.UpdatedAt = time.Now()
	if err := s.dbRepo.Update(ctx, entity); err != nil {
		return fmt.Errorf("failed to update analysis status: %w", err)
	}

	metrics.AgenticAnalysisDuration.Observe(agenticDuration.Seconds())
	metrics.AgenticAnalysisCompleted.WithLabelValues("success").Inc()
	slog.Info("Analysis status updated to completed", "analysis_id", result.AnalysisID)

	// Post agentic PR comment if this was triggered by a pull_request event
	if entity.PRNumber > 0 && s.prCommentService != nil {
		if err := s.prCommentService.PostAgenticFindings(ctx, entity.RepoFullName, entity.PRNumber, result); err != nil {
			slog.Warn("Failed to post agentic PR comment", "analysis_id", result.AnalysisID, "error", err)
		}
	}

	return nil
}

// GetResult retrieves stored agentic analysis results from object storage.
func (s *agenticAnalysisServiceImpl) GetResult(ctx context.Context, analysisID string) ([]byte, error) {
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
