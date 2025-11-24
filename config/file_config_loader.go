package config

import (
	"errors"
	"fmt"
	"log"
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

	fmt.Printf("MCPGuard - Loading config file %s\n", fileName)
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

	return cfg, nil
}

func getScope() string {
	// If an explicit SCOPE is provided, honor it first.
	scope := os.Getenv("SCOPE")
	if scope != "" {
		log.Println("MCPGuard - Scope (from SCOPE env):", scope)
		return scope
	}

	// Detect Vercel environment: VERCEL is set when running on Vercel.
	// If VERCEL is present and VERCEL_ENV == "production" then use "prod",
	// otherwise default to "local".
	if os.Getenv("VERCEL") != "" {
		vercelEnv := os.Getenv("VERCEL_ENV")
		if strings.EqualFold(vercelEnv, "production") {
			log.Println("MCPGuard - Detected Vercel production environment; using scope: prod")
			return "prod"
		}
		// Non-production Vercel deployments treat as local by default.
		log.Println("MCPGuard - Detected Vercel non-production environment; using scope: local")
		return "local"
	}

	// Fallback to local when nothing else is set.
	scope = "local"
	log.Println("MCPGuard - Scope: ", scope)
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
