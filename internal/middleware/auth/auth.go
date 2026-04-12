package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// Auth creates a generic authentication middleware.
func Auth(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if errMsg := auth.Authenticate(r); errMsg != "" {
				http.Error(w, errMsg, http.StatusUnauthorized)
				return
			}

			if clientID := r.Header.Get(ClientIDHeader); clientID != "" {
				ctx := context.WithValue(r.Context(), ClientIDContextKey, clientID)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WebhookAuth creates a middleware that validates GitHub webhook signatures.
func WebhookAuth(auth Authenticator) func(http.Handler) http.Handler {
	validator, ok := auth.(WebhookSignatureValidator)
	if !ok {
		panic("WebhookAuth requires an authenticator that implements WebhookSignatureValidator")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signature := r.Header.Get(GitHubSignatureHeader)
			if signature == "" {
				http.Error(w, `{"error":"missing_signature","message":"X-Hub-Signature-256 header is required"}`, http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"error":"read_error","message":"Failed to read request body"}`, http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(body))

			if !validator.ValidateSignature(body, signature) {
				http.Error(w, `{"error":"invalid_signature","message":"Invalid webhook signature"}`, http.StatusUnauthorized)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, GitHubEventContextKey, r.Header.Get(GitHubEventHeader))
			ctx = context.WithValue(ctx, GitHubDeliveryContextKey, r.Header.Get(GitHubDeliveryHeader))
			ctx = context.WithValue(ctx, PayloadContextKey, body)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Context helpers

// WithGitHubEvent injects a GitHub event name into the context. Used in tests.
func WithGitHubEvent(ctx context.Context, event string) context.Context {
	return context.WithValue(ctx, GitHubEventContextKey, event)
}

func GetGitHubEventFromContext(ctx context.Context) string {
	if event, ok := ctx.Value(GitHubEventContextKey).(string); ok {
		return event
	}
	return ""
}

func GetGitHubDeliveryFromContext(ctx context.Context) string {
	if delivery, ok := ctx.Value(GitHubDeliveryContextKey).(string); ok {
		return delivery
	}
	return ""
}

func GetPayloadFromContext(ctx context.Context) []byte {
	if payload, ok := ctx.Value(PayloadContextKey).([]byte); ok {
		return payload
	}
	return nil
}

func GetClientIDFromContext(ctx context.Context) string {
	if clientID, ok := ctx.Value(ClientIDContextKey).(string); ok {
		return clientID
	}
	return ""
}
