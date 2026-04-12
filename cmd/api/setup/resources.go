package setup

import (
	"context"
	"fmt"
	"os"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/controller"
	"github.com/FlppFer/MCPGuard/internal/messaging"
	middleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service"
	ghintegration "github.com/FlppFer/MCPGuard/internal/service/github_integration"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"

	// Import rules packages to trigger init() functions that register all analysis rules
	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript/rules"
	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python/rules"
)

type (
	Resources struct {
		WebhookAuthenticator      middleware.Authenticator
		APIKeyAuthenticator       middleware.Authenticator
		GitWebhookController      controller.GitWebhookControllerInterface
		AgenticAnalysisController controller.AgenticAnalysisControllerInterface
		Publisher                 messaging.MessagePublisher
		DBClient                  db.DatabaseClient
		StorageClient             obj_storage.StorageRepository
		AgenticService            service.AgenticAnalysisService
		AgenticEnabled            bool
		PRCommentService          ghintegration.PRCommentService
	}
)

func Bootstrap(ctx context.Context, cfg *config.Config) *Resources {
	dbClient, osClient := initRepositories(cfg)
	webhookAuth, apiKeyAuth := initAuthenticators(cfg)
	staticAnalyzer := static_analysis.NewService(static_analysis.WithPersistence(false))
	agenticService, agenticEnabled := initAgenticService(cfg, dbClient, osClient)
	publisher := initPublisher(cfg)
	queueEnabled := cfg.MessagingCfg != nil && cfg.MessagingCfg.Enabled
	prCommentService := initPRCommentService(cfg)
	gitWebhookService := service.NewGitWebhookService(dbClient, osClient, staticAnalyzer, agenticService, agenticEnabled, publisher, queueEnabled, prCommentService)

	return &Resources{
		WebhookAuthenticator:      webhookAuth,
		APIKeyAuthenticator:       apiKeyAuth,
		GitWebhookController:      controller.NewGitWebhookController(gitWebhookService),
		AgenticAnalysisController: controller.NewAgenticAnalysisController(agenticService),
		Publisher:                 publisher,
		DBClient:                  dbClient,
		StorageClient:             osClient,
		AgenticService:            agenticService,
		AgenticEnabled:            agenticEnabled,
		PRCommentService:          prCommentService,
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

func initPublisher(cfg *config.Config) messaging.MessagePublisher {
	if cfg.MessagingCfg != nil && cfg.MessagingCfg.Enabled {
		publisher, err := messaging.NewRabbitMQPublisher(cfg.MessagingCfg.RabbitMQURL)
		if err != nil {
			panic(fmt.Sprintf("failed to connect to RabbitMQ: %v", err))
		}
		return publisher
	}
	return messaging.NewNoopPublisher()
}

func initPRCommentService(cfg *config.Config) ghintegration.PRCommentService {
	if cfg.GitHubIntegrationCfg == nil || !cfg.GitHubIntegrationCfg.Enabled {
		return ghintegration.NewPRCommentService("", false)
	}
	token := ""
	if cfg.GitHubIntegrationCfg.TokenEnvVar != "" {
		token = os.Getenv(cfg.GitHubIntegrationCfg.TokenEnvVar)
	}
	return ghintegration.NewPRCommentService(token, true)
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
