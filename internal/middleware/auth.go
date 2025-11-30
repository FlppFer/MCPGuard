package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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

			var missingHeaders []string
			if apiKey == "" {
				missingHeaders = append(missingHeaders, APIKeyHeader)
			}
			if clientID == "" {
				missingHeaders = append(missingHeaders, ClientIDHeader)
			}
			if len(missingHeaders) > 0 {
				msg := fmt.Sprintf(`{"error":"missing_headers","message":"Missing required headers: %s"}`, strings.Join(missingHeaders, ", "))
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			// Validate credentials - O(1) lookup by clientID
			if !secretsSvc.ValidateCredentials(clientID, apiKey) {
				http.Error(w, `{"error":"invalid_credentials","message":"Invalid API key or client ID"}`, http.StatusUnauthorized)
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
