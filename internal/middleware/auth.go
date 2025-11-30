package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/FlppFer/MCPGuard/internal/service"
)

const (
	// APIKeyHeader is the header name for API key authentication
	APIKeyHeader = "X-API-Key"
	// ClientIDHeader is the header name for client identification
	ClientIDHeader = "X-Client-ID"
)

// ContextKey type for context values
type ContextKey string

const (
	// ClientIDContextKey is the context key for storing the authenticated client ID
	ClientIDContextKey ContextKey = "client_id"
)

// APIKeyAuth creates a middleware that validates API keys using the secrets service.
// It validates X-API-Key and X-Client-ID headers and ensures they match.
func APIKeyAuth(secretsSvc service.SecretsService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If auth is not enabled, pass through
			if !secretsSvc.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			apiKey := r.Header.Get(APIKeyHeader)
			clientID := r.Header.Get(ClientIDHeader)

			if apiKey == "" {
				http.Error(w, `{"error":"missing_api_key","message":"X-API-Key header is required"}`, http.StatusUnauthorized)
				return
			}

			if clientID == "" {
				http.Error(w, `{"error":"missing_client_id","message":"X-Client-ID header is required"}`, http.StatusUnauthorized)
				return
			}

			// Validate API key and get expected client ID
			expectedClientID, valid := secretsSvc.ValidateAPIKey(apiKey)
			if !valid {
				http.Error(w, `{"error":"invalid_api_key","message":"Invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// Verify client ID matches (constant-time comparison)
			if subtle.ConstantTimeCompare([]byte(clientID), []byte(expectedClientID)) != 1 {
				http.Error(w, `{"error":"client_mismatch","message":"X-Client-ID does not match API key"}`, http.StatusUnauthorized)
				return
			}

			// Add client ID to context for downstream handlers
			ctx := context.WithValue(r.Context(), ClientIDContextKey, clientID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClientIDFromContext retrieves the authenticated client ID from the request context
func GetClientIDFromContext(ctx context.Context) string {
	if clientID, ok := ctx.Value(ClientIDContextKey).(string); ok {
		return clientID
	}
	return ""
}
