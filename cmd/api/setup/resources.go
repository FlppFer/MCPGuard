package setup

import (
	"context"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/controller"
	middleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"

	// Import rules package to trigger init() functions that register all analysis rules
	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python/rules"
)

type (
	Resources struct {
		WebhookAuthenticator      middleware.Authenticator
		APIKeyAuthenticator       middleware.Authenticator
		GitWebhookController      controller.GitWebhookControllerInterface
		AgenticAnalysisController controller.AgenticAnalysisControllerInterface
	}
)

func Bootstrap(ctx context.Context, cfg *config.Config) *Resources {
	dbClient, osClient := initRepositories(cfg)
	webhookAuth, apiKeyAuth := initAuthenticators(cfg)
	staticAnalyzer := static_analysis.NewService(static_analysis.WithPersistence(false))
	agenticService, agenticEnabled := initAgenticService(cfg, dbClient, osClient)
	gitWebhookService := service.NewGitWebhookService(dbClient, osClient, staticAnalyzer, agenticService, agenticEnabled)

	return &Resources{
		WebhookAuthenticator:      webhookAuth,
		APIKeyAuthenticator:       apiKeyAuth,
		GitWebhookController:      controller.NewGitWebhookController(gitWebhookService),
		AgenticAnalysisController: controller.NewAgenticAnalysisController(agenticService),
	}
}

func initRepositories(cfg *config.Config) (db.DatabaseClient, obj_storage.StorageRepository) {
	dbClient, err := db.NewDatabaseClient(cfg.DbCfg)
	if err != nil {
		panic(err)
	}

	osClient, err := obj_storage.NewObjectStorageClient(cfg.ObjectStorageCfg)
	if err != nil {
		panic(err)
	}

	return dbClient, osClient
}

func initAuthenticators(cfg *config.Config) (middleware.Authenticator, middleware.Authenticator) {
	if cfg.AuthCfg == nil {
		panic("auth configuration is required")
	}
	if cfg.AuthCfg.WebhookSecretKey == "" {
		panic("auth.webhook_secret_key must be configured")
	}
	if cfg.AuthCfg.APIKeysKey == "" {
		panic("auth.api_keys_key must be configured")
	}

	webhookAuth := middleware.NewWebhookAuthenticator(cfg.AuthCfg.WebhookSecretKey)
	apiKeyAuth := middleware.NewAPIKeyAuthenticator(cfg.AuthCfg.APIKeysKey)
	return webhookAuth, apiKeyAuth
}

func initAgenticService(
	cfg *config.Config,
	dbClient db.DatabaseClient,
	osClient obj_storage.StorageRepository,
) (service.AgenticAnalysisService, bool) {
	if cfg.AgenticCfg == nil || !cfg.AgenticCfg.Enabled {
		return service.NewAgenticAnalysisService(dbClient, osClient, "", false), false
	}

	if cfg.AgenticCfg.Mock {
		return service.NewMockAgenticAnalysisService(dbClient, osClient), true
	}

	return service.NewAgenticAnalysisService(dbClient, osClient, cfg.AgenticCfg.WorkerURL, true), true
}
