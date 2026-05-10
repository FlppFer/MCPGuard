package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

type webhookAuthenticator struct {
	secret string
}

// NewWebhookAuthenticator creates a new webhook signature authenticator.
// Panics if the environment variable is not set or empty.
func NewWebhookAuthenticator(secretEnvKey string) Authenticator {
	secret := os.Getenv(secretEnvKey)
	if secret == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", secretEnvKey))
	}

	slog.Info("Webhook authenticator initialized", "env_key", secretEnvKey)
	return &webhookAuthenticator{secret: secret}
}

func (a *webhookAuthenticator) Name() string {
	return "webhook"
}

func (a *webhookAuthenticator) Authenticate(r *http.Request) string {
	signature := r.Header.Get(GitHubSignatureHeader)
	if signature == "" {
		return `{"error":"missing_signature","message":"X-Hub-Signature-256 header is required"}`
	}
	return ""
}

func (a *webhookAuthenticator) ValidateSignature(payload []byte, signature string) bool {
	if a.secret == "" || signature == "" {
		slog.Warn("Webhook validation failed: empty secret or signature",
			"secret_empty", a.secret == "",
			"signature_empty", signature == "")
		return false
	}

	const prefix = "sha256="
	if len(signature) < len(prefix) || signature[:len(prefix)] != prefix {
		slog.Warn("Webhook validation failed: invalid signature prefix",
			"signature", signature)
		return false
	}

	receivedMAC, err := hex.DecodeString(signature[len(prefix):])
	if err != nil {
		slog.Warn("Webhook validation failed: could not decode signature",
			"error", err)
		return false
	}

	mac := hmac.New(sha256.New, []byte(a.secret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	valid := hmac.Equal(receivedMAC, expectedMAC)
	if !valid {
		slog.Warn("Webhook signature mismatch — check that GITHUB_WEBHOOK_SECRET matches the secret configured in GitHub")
	}
	return valid
}
