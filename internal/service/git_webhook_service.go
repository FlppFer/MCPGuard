package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	repositories2 "github.com/FlppFer/MCPGuard/internal/model/repositories"
	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/utils"
	"github.com/google/uuid"
)

type GitWebhookService interface {
	RequestAnalysis(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
	GetAnalysisStatus(ctx context.Context, analysisID string) (*services.AnalysisStatusDTO, error)
	GetAnalysisResult(ctx context.Context, analysisID string) ([]byte, error)
}

type gitWebhookServiceImpl struct {
	dbRepo         db.DatabaseClient             // SQLite GORM implementation
	storageRepo    obj_storage.StorageRepository // S3/Local obj_storage implementation
	staticAnalyzer static_analysis.Service       // Static analysis service
}

func NewGitWebhookService(
	dbRepo db.DatabaseClient,
	storageRepo obj_storage.StorageRepository,
	staticAnalyzer static_analysis.Service,
) GitWebhookService {

	return &gitWebhookServiceImpl{
		dbRepo:         dbRepo,
		storageRepo:    storageRepo,
		staticAnalyzer: staticAnalyzer,
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
		Status:    "created",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.dbRepo.Create(ctx, entity); err != nil {
		return nil, err
	}

	// 2. Download repository locally
	repo, err := utils.DownloadRepo(repoURL, branch, commit)
	if err != nil {
		entity.Status = "clone_failed"
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
	}

	entity.SourceArchivePath = repo.ZipPath
	entity.Status = "downloaded"
	uc.dbRepo.Update(ctx, entity)

	// 3. Upload ZIP to object obj_storage
	err = uc.storageRepo.UploadFile(ctx, analysisID+".zip", repo.ZipPath)
	if err != nil {
		entity.Status = "storage_upload_failed"
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
		entity.Status = "parse_failed"
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
	}

	// 5. Update status to indicate static analysis started
	entity.Status = "static_analysis_started"
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
			entity.Status = "static_analysis_failed"
			entity.ErrorMessage = err.Error()
			uc.dbRepo.Update(context.Background(), entity)
			return
		}

		// Upload results to object storage
		if err := uc.uploadAnalysisResult(asyncCtx, analysisID, result); err != nil {
			slog.Error("Failed to upload analysis results", "analysis_id", analysisID, "error", err)
			entity.Status = "storage_upload_failed"
			entity.ErrorMessage = err.Error()
			uc.dbRepo.Update(context.Background(), entity)
			return
		}

		// Update DB success state
		entity.Status = "static_done"
		entity.UpdatedAt = time.Now()
		uc.dbRepo.Update(context.Background(), entity)
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
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s_static.json", analysisID))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Upload to object storage
	s3Key := fmt.Sprintf("analysis-results/%s_static.json", analysisID)
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

	if entity.Status != "static_done" && entity.Status != "completed" {
		return nil, fmt.Errorf("%w, current status: %s", ErrAnalysisNotComplete, entity.Status)
	}

	// Download result from S3
	s3Key := fmt.Sprintf("analysis-results/%s_static.json", analysisID)
	data, err := uc.storageRepo.DownloadFile(ctx, s3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to download result: %w", err)
	}

	return data, nil
}
