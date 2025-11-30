package setup

import (
	"context"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/controller"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"

	// Import rules package to trigger init() functions that register all analysis rules
	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python/rules"
)

type (
	Resources struct {
		GitWebhookController      controller.GitWebhookControllerInterface
		AgenticAnalysisController controller.AgenticAnalysisControllerInterface
	}
)

func Bootstrap(ctx context.Context, cfg *config.Config) *Resources {
	dbClient, err := db.NewDatabaseClient(cfg.DbCfg)
	if err != nil {
		panic(err)
	}

	osClient, err := obj_storage.NewObjectStorageClient(cfg.ObjectStorageCfg)
	if err != nil {
		panic(err)
	}

	// Create engine with local persistence disabled (results go to S3)
	staticAnalyzerEngine := static_analysis_engine.NewStaticAnalyzerEngine(
		static_analysis_engine.WithPersistence(false),
	)

	gitWebhookService := service.NewGitWebhookService(dbClient, osClient, staticAnalyzerEngine)
	return &Resources{
		GitWebhookController:      controller.NewGitWebhookController(gitWebhookService),
		AgenticAnalysisController: controller.NewAgenticAnalysisController(),
	}
}
