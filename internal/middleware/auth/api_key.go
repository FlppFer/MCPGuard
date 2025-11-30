package middleware

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

type apiKeyAuthenticator struct {
	clientToAPIKey map[string]string
}

// NewAPIKeyAuthenticator creates a new API key authenticator.
// Format: "client_id:api_key,client_id2:api_key2"
// Panics if the environment variable is not set or has no valid entries.
func NewAPIKeyAuthenticator(apiKeysEnvKey string) Authenticator {
	envValue := os.Getenv(apiKeysEnvKey)
	if envValue == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", apiKeysEnvKey))
	}

	clientToAPIKey := make(map[string]string)

	for _, pair := range strings.Split(envValue, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			slog.Warn("Invalid API key format, expected 'client_id:api_key'", "entry", pair)
			continue
		}

		clientID := strings.TrimSpace(parts[0])
		apiKey := strings.TrimSpace(parts[1])

		if clientID == "" || apiKey == "" {
			slog.Warn("Empty client ID or API key", "entry", pair)
			continue
		}

		clientToAPIKey[clientID] = apiKey
	}

	if len(clientToAPIKey) == 0 {
		panic(fmt.Sprintf("no valid API keys found in %s", apiKeysEnvKey))
	}

	slog.Info("API key authenticator initialized", "env_key", apiKeysEnvKey, "client_count", len(clientToAPIKey))
	return &apiKeyAuthenticator{clientToAPIKey: clientToAPIKey}
}

func (a *apiKeyAuthenticator) Name() string {
	return "api_key"
}

func (a *apiKeyAuthenticator) Authenticate(r *http.Request) string {
	apiKey := r.Header.Get(APIKeyHeader)
	clientID := r.Header.Get(ClientIDHeader)

	if apiKey == "" && clientID == "" {
		return fmt.Sprintf(`{"error":"missing_headers","message":"Missing required headers: %s, %s"}`, APIKeyHeader, ClientIDHeader)
	}
	if apiKey == "" {
		return fmt.Sprintf(`{"error":"missing_header","message":"Missing required header: %s"}`, APIKeyHeader)
	}
	if clientID == "" {
		return fmt.Sprintf(`{"error":"missing_header","message":"Missing required header: %s"}`, ClientIDHeader)
	}

	expectedKey, exists := a.clientToAPIKey[clientID]
	if !exists {
		return `{"error":"invalid_credentials","message":"Invalid API key or client ID"}`
	}

	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedKey)) != 1 {
		return `{"error":"invalid_credentials","message":"Invalid API key or client ID"}`
	}

	return ""
}
