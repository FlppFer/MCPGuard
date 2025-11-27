package setup

import (
	"context"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/controller"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
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

	staticAnalyzerEngine := static_analysis_engine.NewStaticAnalyzerEngine()

	gitWebhookService := service.NewGitWebhookService(dbClient, osClient, staticAnalyzerEngine)
	return &Resources{
		GitWebhookController:      controller.NewGitWebhookController(gitWebhookService),
		AgenticAnalysisController: controller.NewAgenticAnalysisController(),
	}
}
