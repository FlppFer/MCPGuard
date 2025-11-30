package service

import (
	"crypto/subtle"
	"log/slog"
	"os"
	"strings"
)

// SecretsService manages API key to client ID mappings from environment variables
type SecretsService interface {
	// ValidateCredentials checks if the API key matches the expected key for the given client ID
	ValidateCredentials(clientID, apiKey string) bool
	// IsEnabled returns true if authentication is configured
	IsEnabled() bool
}

type secretsServiceImpl struct {
	// clientToAPIKey maps client IDs to their API keys
	clientToAPIKey map[string]string
	enabled        bool
}

// NewSecretsService creates a new secrets service that loads API keys from environment variables.
// Environment variable format: MCPGUARD_API_KEYS="client1:key1,client2:key2,client3:key3"
// Each entry is "client_id:api_key" separated by commas.
func NewSecretsService() SecretsService {
	s := &secretsServiceImpl{
		clientToAPIKey: make(map[string]string),
		enabled:        false,
	}

	// Load from environment variable
	envKeys := os.Getenv("MCPGUARD_API_KEYS")
	if envKeys == "" {
		slog.Warn("MCPGUARD_API_KEYS not set - authentication disabled")
		return s
	}

	// Parse format: "client1:key1,client2:key2"
	pairs := strings.Split(envKeys, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			slog.Warn("Invalid API key format, expected 'client_id:key'", "entry", pair)
			continue
		}

		clientID := strings.TrimSpace(parts[0])
		apiKey := strings.TrimSpace(parts[1])

		if apiKey == "" || clientID == "" {
			slog.Warn("Empty API key or client ID", "entry", pair)
			continue
		}

		s.clientToAPIKey[clientID] = apiKey
	}

	if len(s.clientToAPIKey) > 0 {
		s.enabled = true
		slog.Info("Loaded API keys from environment", "count", len(s.clientToAPIKey))
	} else {
		slog.Warn("No valid API keys found in MCPGUARD_API_KEYS")
	}

	return s
}

func (s *secretsServiceImpl) ValidateCredentials(clientID, apiKey string) bool {
	expectedKey, exists := s.clientToAPIKey[clientID]
	if !exists {
		return false
	}
	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedKey)) == 1
}

func (s *secretsServiceImpl) IsEnabled() bool {
	return s.enabled
}
