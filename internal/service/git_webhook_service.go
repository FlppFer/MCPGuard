package service

import (
	"context"
	"log"
	"time"

	repositories2 "github.com/FlppFer/MCPGuard/internal/model/repositories"
	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/utils"
	"github.com/google/uuid"
)

type GitWebhookService interface {
	RequestAnalysis(ctx context.Context, repoURL, branch, commit string) (*services.GitWebhookAnalysisResultDTO, error)
}

type gitWebhookServiceImpl struct {
	dbRepo         db.DatabaseClient             // SQLite GORM implementation
	storageRepo    obj_storage.StorageRepository // S3/Local obj_storage implementation
	staticAnalyzer StaticAnalysisService         // Your static analysis engine
}

func NewGitWebhookService(
	dbRepo db.DatabaseClient,
	storageRepo obj_storage.StorageRepository,
	staticAnalyzer StaticAnalysisService,
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
	repo, err := utils.DownloadRepo(repoURL, commit)
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
	err = uc.storageRepo.Upload(ctx, analysisID+".zip", repo.ZipPath)
	if err != nil {
		entity.Status = "storage_upload_failed"
		entity.ErrorMessage = err.Error()
		uc.dbRepo.Update(ctx, entity)
		return nil, err
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
	go func() {
		err := uc.staticAnalyzer.RunStaticAnalysis(ctx, analysisID, parsedFiles)
		if err != nil {
			log.Println("Static analysis failed:", err)
			entity.Status = "static_analysis_failed"
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
