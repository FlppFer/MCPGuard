package service

import (
	"log/slog"
	"os"
	"strings"
)

// SecretsService manages API key to client ID mappings from environment variables
type SecretsService interface {
	// ValidateAPIKey checks if the API key is valid and returns the associated client ID
	ValidateAPIKey(apiKey string) (clientID string, valid bool)
	// GetClientID returns the client ID for a given API key, empty if not found
	GetClientID(apiKey string) string
	// IsEnabled returns true if authentication is configured
	IsEnabled() bool
}

type secretsServiceImpl struct {
	// apiKeyToClient maps API keys to their client IDs
	apiKeyToClient map[string]string
	enabled        bool
}

// NewSecretsService creates a new secrets service that loads API keys from environment variables.
// Environment variable format: MCPGUARD_API_KEYS="key1:client1,key2:client2,key3:client3"
// Each entry is "api_key:client_id" separated by commas.
func NewSecretsService() SecretsService {
	s := &secretsServiceImpl{
		apiKeyToClient: make(map[string]string),
		enabled:        false,
	}

	// Load from environment variable
	envKeys := os.Getenv("MCPGUARD_API_KEYS")
	if envKeys == "" {
		slog.Warn("MCPGUARD_API_KEYS not set - authentication disabled")
		return s
	}

	// Parse format: "key1:client1,key2:client2"
	pairs := strings.Split(envKeys, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			slog.Warn("Invalid API key format, expected 'key:client_id'", "entry", pair)
			continue
		}

		apiKey := strings.TrimSpace(parts[0])
		clientID := strings.TrimSpace(parts[1])

		if apiKey == "" || clientID == "" {
			slog.Warn("Empty API key or client ID", "entry", pair)
			continue
		}

		s.apiKeyToClient[apiKey] = clientID
	}

	if len(s.apiKeyToClient) > 0 {
		s.enabled = true
		slog.Info("Loaded API keys from environment", "count", len(s.apiKeyToClient))
	} else {
		slog.Warn("No valid API keys found in MCPGUARD_API_KEYS")
	}

	return s
}

func (s *secretsServiceImpl) ValidateAPIKey(apiKey string) (string, bool) {
	clientID, exists := s.apiKeyToClient[apiKey]
	return clientID, exists
}

func (s *secretsServiceImpl) GetClientID(apiKey string) string {
	return s.apiKeyToClient[apiKey]
}

func (s *secretsServiceImpl) IsEnabled() bool {
	return s.enabled
}
