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
	dbClient, err := db.NewDatabaseClient(cfg.DbCfg)
	if err != nil {
		panic(err)
	}

	osClient, err := obj_storage.NewObjectStorageClient(cfg.ObjectStorageCfg)
	if err != nil {
		panic(err)
	}

	// Create static analysis service with local persistence disabled (results go to S3)
	staticAnalysisService := static_analysis.NewService(
		static_analysis.WithPersistence(false),
	)

	// Create authenticators from config
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

	gitWebhookService := service.NewGitWebhookService(dbClient, osClient, staticAnalysisService)
	return &Resources{
		WebhookAuthenticator:      webhookAuth,
		APIKeyAuthenticator:       apiKeyAuth,
		GitWebhookController:      controller.NewGitWebhookController(gitWebhookService),
		AgenticAnalysisController: controller.NewAgenticAnalysisController(),
	}
}
