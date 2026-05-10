package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadConfig() (*Config, error) {
	scope := getScope()
	return LoadConfigByScope(scope)
}

func LoadConfigByScope(scope string) (*Config, error) {
	fileName, err := getFileNameConfigByScope(scope)
	if err != nil {
		return nil, err
	}

	slog.Info("MCPGuard - Loading config file", "file", fileName)
	return readFileConfig(fileName)
}

func getFileNameConfigByScope(scope string) (string, error) {
	configFileNames, err := getAllConfigFiles()
	if err != nil {
		return "", err
	}

	scopeLower := strings.ToLower(scope)

	// if scope is a file name, return it
	if contains(configFileNames, scopeLower) {
		return convertToYmlFile(scopeLower), nil
	}

	// treat local as default
	if scopeLower == "local" {
		return convertToYmlFile("default"), nil
	}

	// if scope contains a default config name, return it (e.g. "production", "prod")
	defaultConfigs := []string{
		"default",
		"prod",
	}
	for _, defaultConfig := range defaultConfigs {
		if strings.Contains(scopeLower, defaultConfig) {
			return convertToYmlFile(defaultConfig), nil
		}
	}

	return "", errors.New("no config file found")
}

func convertToYmlFile(fileName string) string {
	return strings.ToLower(fmt.Sprintf("%v%v", fileName, ymlExtension))
}

func getAllConfigFiles() ([]string, error) {
	configFiles, err := cfgFiles.ReadDir(".")
	if err != nil {
		return nil, err
	}

	var fileNames []string
	for _, file := range configFiles {
		fileName := strings.TrimSuffix(file.Name(), ymlExtension)
		fileNames = append(fileNames, fileName)
	}

	return fileNames, nil
}

func readFileConfig(fileName string) (*Config, error) {
	content, err := cfgFiles.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var cfg *Config
	if err = yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("ERROR - Failed to parse config file. %w", err)
	}

	applyEnvOverrides(cfg)

	return cfg, nil
}

// applyEnvOverrides applies runtime environment variable overrides to the config
// so infrastructure settings (e.g. RABBITMQ_URL) can be configured without
// rebuilding images. Presence of RABBITMQ_URL implicitly enables messaging.
func applyEnvOverrides(cfg *Config) {
	if cfg == nil {
		return
	}
	if url := os.Getenv("RABBITMQ_URL"); url != "" {
		if cfg.MessagingCfg == nil {
			cfg.MessagingCfg = &MessagingConfig{}
		}
		cfg.MessagingCfg.RabbitMQURL = url
		cfg.MessagingCfg.Enabled = true
		slog.Info("MCPGuard - Messaging enabled via RABBITMQ_URL env override")
	}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		if cfg.DbCfg == nil {
			cfg.DbCfg = &DatabaseConfig{}
		}
		cfg.DbCfg.Provider = "postgres"
		cfg.DbCfg.DSN = dsn
		cfg.DbCfg.Mock = false
		slog.Info("MCPGuard - Postgres enabled via DATABASE_URL env override")
	}
}

func getScope() string {
	// If an explicit SCOPE is provided, honor it first.
	scope := os.Getenv("SCOPE")
	if scope != "" {
		slog.Info("MCPGuard - Scope (from SCOPE env)", "scope", scope)
		return scope
	}

	// Detect Vercel environment: VERCEL is set when running on Vercel.
	// If VERCEL is present and VERCEL_ENV == "production" then use "prod",
	// otherwise default to "local".
	if os.Getenv("VERCEL") != "" {
		vercelEnv := os.Getenv("VERCEL_ENV")
		if strings.EqualFold(vercelEnv, "production") {
			slog.Info("MCPGuard - Detected Vercel production environment", "scope", "prod")
			return "prod"
		}
		// Non-production Vercel deployments treat as local by default.
		slog.Info("MCPGuard - Detected Vercel non-production environment", "scope", "local")
		return "local"
	}

	// Fallback to local when nothing else is set.
	scope = "local"
	slog.Info("MCPGuard - Scope", "scope", scope)
	return scope
}

func contains(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}
