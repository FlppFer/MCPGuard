package config

import "embed"

const (
	ymlExtension = ".yaml"
)

//go:embed *.yaml
var cfgFiles embed.FS

type (
	Config struct {
		Scope                string                   `yaml:"scope"`
		LogLevel             string                   `yaml:"log-level"`
		DbCfg                *DatabaseConfig          `yaml:"data_base"`
		ObjectStorageCfg     *ObjectStorageConfig     `yaml:"object_storage"`
		AuthCfg              *AuthConfig              `yaml:"auth"`
		AgenticCfg           *AgenticConfig           `yaml:"agentic"`
		MessagingCfg         *MessagingConfig         `yaml:"messaging"`
		GitHubIntegrationCfg *GitHubIntegrationConfig `yaml:"github_integration"`
	}

	MessagingConfig struct {
		Enabled     bool   `yaml:"enabled"`
		RabbitMQURL string `yaml:"rabbitmq_url"`
	}

	GitHubIntegrationConfig struct {
		Enabled     bool   `yaml:"enabled"`
		TokenEnvVar string `yaml:"token_env_var"`
	}

	AgenticConfig struct {
		Enabled   bool   `yaml:"enabled"`
		Mock      bool   `yaml:"mock"`
		WorkerURL string `yaml:"worker_url"`
	}

	AuthConfig struct {
		WebhookSecretKey string `yaml:"webhook_secret_key"` // Env var name for webhook secret
		APIKeysKey       string `yaml:"api_keys_key"`       // Env var name for API keys (format: "client_id:api_key,...")
	}

	DatabaseConfig struct {
		// Provider selects the backend: "sqlite" (default) or "postgres".
		Provider string `yaml:"provider"`
		// Mock enables the ephemeral in-process SQLite DB — for unit tests only.
		Mock bool `yaml:"mock"`
		// Path is the SQLite file path (used when Provider=="sqlite").
		Path string `yaml:"path"`
		// DSN is the Postgres connection string (used when Provider=="postgres").
		// Can be overridden at runtime by the DATABASE_URL env var.
		DSN string `yaml:"dsn"`
	}

	// ObjectStorageConfig configures the storage backend.
	// Provider must be one of: "localstack", "s3".
	ObjectStorageConfig struct {
		Provider string    `yaml:"provider"`
		BasePath string    `yaml:"base-path"`
		S3       *S3Config `yaml:"s3"`
	}

	S3Config struct {
		Bucket         string `yaml:"bucket"`
		Region         string `yaml:"region"`
		Endpoint       string `yaml:"endpoint"`
		ForcePathStyle bool   `yaml:"force-path-style"`
	}
)
