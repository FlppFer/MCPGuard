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
	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/utils"
	"github.com/google/uuid"
)

type GitWebhookService interface {
	RequestAnalysis(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
	GetAnalysisStatus(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error)
	GetAnalysisResult(ctx context.Context, analysisID string) ([]byte, error)
	GetMergedResult(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error)
}

type gitWebhookServiceImpl struct {
	dbRepo         db.DatabaseClient
	storageRepo    obj_storage.StorageRepository
	staticAnalyzer static_analysis.Service
	agenticService AgenticAnalysisService
	agenticEnabled bool
}

func NewGitWebhookService(
	dbRepo db.DatabaseClient,
	storageRepo obj_storage.StorageRepository,
	staticAnalyzer static_analysis.Service,
	agenticService AgenticAnalysisService,
	agenticEnabled bool,
) GitWebhookService {
	return &gitWebhookServiceImpl{
		dbRepo:         dbRepo,
		storageRepo:    storageRepo,
		staticAnalyzer: staticAnalyzer,
		agenticService: agenticService,
		agenticEnabled: agenticEnabled,
	}
}

func (uc *gitWebhookServiceImpl) RequestAnalysis(
	ctx context.Context,
	repoURL, branch, commit string,
) (*services.GitWebhookAnalysisResultDTO, error) {

	analysisID := uuid.NewString()

	// 1. Create analysis entity
	entity := &repositories2.AnalysisEntity{
		ID:        analysisID,
		RepoURL:   repoURL,
		Branch:    branch,
		Commit:    commit,
		Status:    repositories2.StatusCreated.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.dbRepo.Create(ctx, entity); err != nil {
		return nil, err
	}

	// 2. Download repository locally
	repo, err := utils.DownloadRepo(repoURL, branch, commit)
	if err != nil {
		entity.Status = repositories2.StatusFailed.String()
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
	}

	entity.SourceArchivePath = repo.ZipPath
	entity.Status = repositories2.StatusDownloadingRepo.String()
	uc.dbRepo.Update(ctx, entity)

	// 3. Upload ZIP to object obj_storage
	err = uc.storageRepo.UploadFile(ctx, fmt.Sprintf(S3KeySourceArchive, analysisID), repo.ZipPath)
	if err != nil {
		entity.Status = repositories2.StatusFailed.String()
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
	}

	// Clean up zip file after successful upload
	if err := os.Remove(repo.ZipPath); err != nil {
		slog.Warn("Failed to clean up zip file", "path", repo.ZipPath, "error", err)
	}

	// 4. Parse repository files
	parsedFiles, err := utils.ParseRepositoryFiles(repo.LocalPath)
	if err != nil {
		entity.Status = repositories2.StatusFailed.String()
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
	}

	// 5. Update status to indicate static analysis started
	entity.Status = repositories2.StatusStaticAnalysisRunning.String()
	entity.UpdatedAt = time.Now()
	uc.dbRepo.Update(ctx, entity)

	// 6. Trigger async static analysis
	// Use background context since the HTTP request context will be cancelled after response
	go func() {
		// Clean up cloned repo when done (success or failure)
		defer func() {
			if err := os.RemoveAll(repo.LocalPath); err != nil {
				slog.Warn("Failed to clean up cloned repo", "path", repo.LocalPath, "error", err)
			}
		}()

		asyncCtx := context.Background()

		// Run analysis and get results directly (no local file saving)
		result, err := uc.staticAnalyzer.RunAnalysis(asyncCtx, analysisID, parsedFiles)
		if err != nil {
			slog.Error("Static analysis failed", "analysis_id", analysisID, "error", err)
			entity.Status = repositories2.StatusFailed.String()
			entity.ErrorMessage = err.Error()
			uc.dbRepo.Update(context.Background(), entity)
			return
		}

		// Upload results to object storage
		if err := uc.uploadAnalysisResult(asyncCtx, analysisID, result); err != nil {
			slog.Error("Failed to upload analysis results", "analysis_id", analysisID, "error", err)
			entity.Status = repositories2.StatusFailed.String()
			entity.ErrorMessage = err.Error()
			uc.dbRepo.Update(context.Background(), entity)
			return
		}

		// Update DB success state
		entity.Status = repositories2.StatusStaticAnalysisDone.String()
		entity.UpdatedAt = time.Now()
		uc.dbRepo.Update(context.Background(), entity)

		// Optionally trigger agentic analysis
		uc.submitAgenticAnalysis(asyncCtx, entity, analysisID, repoURL, branch, commit)
	}()

	// 7. Respond to webhook
	return &services.GitWebhookAnalysisResultDTO{
		AnalysisID: analysisID,
		Status:     repositories2.StatusCreated.String(),
		Timestamp:  time.Now(),
	}, nil
}

// uploadAnalysisResult serializes the analysis result to JSON and uploads it to object storage
func (uc *gitWebhookServiceImpl) uploadAnalysisResult(ctx context.Context, analysisID string, result interface{}) error {
	// Serialize result to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis result: %w", err)
	}

	// Write to temp file (required by storage interface)
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(TmpFileStaticResult, analysisID))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Upload to object storage
	s3Key := fmt.Sprintf(S3KeyStaticResult, analysisID)
	if err := uc.storageRepo.UploadFile(ctx, s3Key, tmpFile); err != nil {
		return fmt.Errorf("failed to upload to storage: %w", err)
	}

	slog.Info("Analysis results uploaded to storage", "analysis_id", analysisID, "s3_key", s3Key)
	return nil
}

// GetAnalysisStatus retrieves the current status of an analysis from the database
func (uc *gitWebhookServiceImpl) GetAnalysisStatus(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error) {
	entity, err := uc.dbRepo.FindByID(ctx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	return &services.AnalysisStatusDTO{
		AnalysisID:   entity.ID,
		RepoURL:      entity.RepoURL,
		Branch:       entity.Branch,
		Commit:       entity.Commit,
		Status:       entity.Status,
		ErrorMessage: entity.ErrorMessage,
		CreatedAt:    entity.CreatedAt,
		UpdatedAt:    entity.UpdatedAt,
	}, nil
}

// GetAnalysisResult retrieves the analysis result JSON from object storage
func (uc *gitWebhookServiceImpl) GetAnalysisResult(ctx context.Context, analysisID string) ([]byte, error) {
	// First check if analysis exists and is complete
	entity, err := uc.dbRepo.FindByID(ctx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	if entity.Status != repositories2.StatusStaticAnalysisDone.String() && entity.Status != repositories2.StatusCompleted.String() {
		return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
	}

	// Download result from S3
	s3Key := fmt.Sprintf(S3KeyStaticResult, analysisID)
	data, err := uc.storageRepo.DownloadFile(ctx, s3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to download result: %w", err)
	}

	return data, nil
}

// GetMergedResult retrieves both static and agentic results and returns a combined DTO.
func (uc *gitWebhookServiceImpl) GetMergedResult(ctx context.Context, analysisID string) (*services.MergedAnalysisResultDTO, error) {
	entity, err := uc.dbRepo.FindByID(ctx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, err.Error())
	}

	if entity.Status != repositories2.StatusStaticAnalysisDone.String() && entity.Status != repositories2.StatusCompleted.String() {
		return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
	}

	merged := &services.MergedAnalysisResultDTO{
		AnalysisID: analysisID,
		Status:     entity.Status,
	}

	merged.StaticResult = uc.downloadStaticResult(ctx, analysisID)
	merged.AgenticResult = uc.downloadAgenticResult(ctx, analysisID)

	return merged, nil
}

func (uc *gitWebhookServiceImpl) downloadStaticResult(ctx context.Context, analysisID string) *model.AnalysisResult {
	s3Key := fmt.Sprintf(S3KeyStaticResult, analysisID)
	data, err := uc.storageRepo.DownloadFile(ctx, s3Key)
	if err != nil {
		slog.Warn("Failed to download static result for merge", "analysis_id", analysisID, "error", err)
		return nil
	}

	var result model.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		slog.Warn("Failed to unmarshal static result", "analysis_id", analysisID, "error", err)
		return nil
	}
	return &result
}

func (uc *gitWebhookServiceImpl) downloadAgenticResult(ctx context.Context, analysisID string) *httpmodel.AgenticAnalysisResultDTO {
	s3Key := fmt.Sprintf(S3KeyAgenticResult, analysisID)
	data, err := uc.storageRepo.DownloadFile(ctx, s3Key)
	if err != nil {
		return nil
	}

	var result httpmodel.AgenticAnalysisResultDTO
	if err := json.Unmarshal(data, &result); err != nil {
		slog.Warn("Failed to unmarshal agentic result", "analysis_id", analysisID, "error", err)
		return nil
	}
	return &result
}

// submitAgenticAnalysis optionally triggers agentic analysis after static analysis succeeds.
func (uc *gitWebhookServiceImpl) submitAgenticAnalysis(
	ctx context.Context,
	entity *repositories2.AnalysisEntity,
	analysisID, repoURL, branch, commit string,
) {
	if !uc.agenticEnabled {
		return
	}

	entity.Status = repositories2.StatusWaitingAgentAnalysis.String()
	entity.UpdatedAt = time.Now()
	uc.dbRepo.Update(ctx, entity)

	agenticReq := &httpmodel.AgenticAnalysisRequestDTO{
		AnalysisID: analysisID,
		RepoURL:    repoURL,
		Branch:     branch,
		Commit:     commit,
		SourceKey:  fmt.Sprintf(S3KeySourceArchive, analysisID),
	}

	if err := uc.agenticService.SubmitForAnalysis(ctx, agenticReq); err != nil {
		slog.Warn("Failed to submit agentic analysis, continuing without it",
			"analysis_id", analysisID, "error", err)
		// Revert to static_analysis_done since agentic couldn't start
		entity.Status = repositories2.StatusStaticAnalysisDone.String()
		entity.UpdatedAt = time.Now()
		uc.dbRepo.Update(ctx, entity)
	}
}
