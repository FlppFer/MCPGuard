package middleware

import "net/http"

// Header constants
const (
	GitHubSignatureHeader = "X-Hub-Signature-256"
	GitHubEventHeader     = "X-GitHub-Event"
	GitHubDeliveryHeader  = "X-GitHub-Delivery"
	APIKeyHeader          = "X-API-Key"
	ClientIDHeader        = "X-Client-ID"
)

// ContextKey type for context values
type ContextKey string

// Context key constants
const (
	GitHubEventContextKey    ContextKey = "github_event"
	GitHubDeliveryContextKey ContextKey = "github_delivery"
	PayloadContextKey        ContextKey = "payload"
	ClientIDContextKey       ContextKey = "client_id"
)

// Authenticator is the common interface for all authentication strategies
type Authenticator interface {
	// Authenticate validates the request and returns an error message if invalid.
	// Returns empty string if authentication succeeds.
	Authenticate(r *http.Request) (errMsg string)
	// Name returns the authenticator name for logging.
	Name() string
}

// WebhookSignatureValidator is implemented by authenticators that validate webhook signatures
type WebhookSignatureValidator interface {
	ValidateSignature(payload []byte, signature string) bool
}
