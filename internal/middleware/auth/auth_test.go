package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockWebhookAuthenticator implements Authenticator and WebhookSignatureValidator for testing
type mockWebhookAuthenticator struct {
	secret string
}

func (m *mockWebhookAuthenticator) Authenticate(r *http.Request) string {
	return ""
}

func (m *mockWebhookAuthenticator) Name() string {
	return "mock_webhook"
}

func (m *mockWebhookAuthenticator) ValidateSignature(payload []byte, signature string) bool {
	if m.secret == "" || signature == "" {
		return false
	}

	const prefix = "sha256="
	if len(signature) < len(prefix) || signature[:len(prefix)] != prefix {
		return false
	}

	receivedMAC, err := hex.DecodeString(signature[len(prefix):])
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(m.secret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(receivedMAC, expectedMAC)
}

func newMockWebhookAuthenticator(secret string) Authenticator {
	return &mockWebhookAuthenticator{secret: secret}
}

// mockAPIKeyAuthenticator implements Authenticator for testing
type mockAPIKeyAuthenticator struct {
	apiKey   string
	clientID string
}

func (m *mockAPIKeyAuthenticator) Authenticate(r *http.Request) string {
	apiKey := r.Header.Get(APIKeyHeader)
	clientID := r.Header.Get(ClientIDHeader)

	if apiKey == "" || clientID == "" {
		return `{"error":"missing_headers","message":"Missing required headers"}`
	}
	if apiKey != m.apiKey || clientID != m.clientID {
		return `{"error":"invalid_credentials","message":"Invalid API key or client ID"}`
	}
	return ""
}

func (m *mockAPIKeyAuthenticator) Name() string {
	return "mock_api_key"
}

func newMockAPIKeyAuthenticator(apiKey, clientID string) Authenticator {
	return &mockAPIKeyAuthenticator{apiKey: apiKey, clientID: clientID}
}

// computeSignature generates a GitHub-style signature for testing
func computeSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookAuth(t *testing.T) {
	secret := "test-webhook-secret"
	mockSvc := newMockWebhookAuthenticator(secret)

	tests := []struct {
		name           string
		payload        string
		signature      string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid signature",
			payload:        `{"action":"push"}`,
			signature:      computeSignature(secret, []byte(`{"action":"push"}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name:           "invalid signature",
			payload:        `{"action":"push"}`,
			signature:      "sha256=invalidsignature0000000000000000000000000000000000000000000000",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_signature",
		},
		{
			name:           "missing signature",
			payload:        `{"action":"push"}`,
			signature:      "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "missing_signature",
		},
		{
			name:           "wrong prefix",
			payload:        `{"action":"push"}`,
			signature:      "sha1=abcdef",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_signature",
		},
		{
			name:           "tampered payload",
			payload:        `{"action":"tampered"}`,
			signature:      computeSignature(secret, []byte(`{"action":"push"}`)),
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			})

			authHandler := WebhookAuth(mockSvc)(handler)

			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(tt.payload))
			if tt.signature != "" {
				req.Header.Set(GitHubSignatureHeader, tt.signature)
			}

			rec := httptest.NewRecorder()
			authHandler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				if rec.Body.String() != tt.expectedBody {
					t.Errorf("expected body %q, got %q", tt.expectedBody, rec.Body.String())
				}
			} else {
				if !strings.Contains(rec.Body.String(), tt.expectedBody) {
					t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rec.Body.String())
				}
			}
		})
	}
}

func TestWebhookAuth_ContextValues(t *testing.T) {
	secret := "test-secret"
	mockSvc := newMockWebhookAuthenticator(secret)

	payload := `{"action":"push"}`
	signature := computeSignature(secret, []byte(payload))

	var capturedEvent, capturedDelivery string
	var capturedPayload []byte

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEvent = GetGitHubEventFromContext(r.Context())
		capturedDelivery = GetGitHubDeliveryFromContext(r.Context())
		capturedPayload = GetPayloadFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	authHandler := WebhookAuth(mockSvc)(handler)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set(GitHubSignatureHeader, signature)
	req.Header.Set(GitHubEventHeader, "push")
	req.Header.Set(GitHubDeliveryHeader, "delivery-123")

	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)

	if capturedEvent != "push" {
		t.Errorf("expected event %q, got %q", "push", capturedEvent)
	}
	if capturedDelivery != "delivery-123" {
		t.Errorf("expected delivery %q, got %q", "delivery-123", capturedDelivery)
	}
	if string(capturedPayload) != payload {
		t.Errorf("expected payload %q, got %q", payload, string(capturedPayload))
	}
}

func TestAPIKeyAuth(t *testing.T) {
	mockAuth := newMockAPIKeyAuthenticator("test-api-key", "test-client")

	tests := []struct {
		name           string
		apiKey         string
		clientID       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid credentials",
			apiKey:         "test-api-key",
			clientID:       "test-client",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name:           "invalid api key",
			apiKey:         "wrong-key",
			clientID:       "test-client",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_credentials",
		},
		{
			name:           "invalid client id",
			apiKey:         "test-api-key",
			clientID:       "wrong-client",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_credentials",
		},
		{
			name:           "missing headers",
			apiKey:         "",
			clientID:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "missing_headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			})

			authHandler := Auth(mockAuth)(handler)

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			if tt.apiKey != "" {
				req.Header.Set(APIKeyHeader, tt.apiKey)
			}
			if tt.clientID != "" {
				req.Header.Set(ClientIDHeader, tt.clientID)
			}

			rec := httptest.NewRecorder()
			authHandler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				if rec.Body.String() != tt.expectedBody {
					t.Errorf("expected body %q, got %q", tt.expectedBody, rec.Body.String())
				}
			} else {
				if !strings.Contains(rec.Body.String(), tt.expectedBody) {
					t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rec.Body.String())
				}
			}
		})
	}
}

func TestAPIKeyAuth_ClientIDInContext(t *testing.T) {
	mockAuth := newMockAPIKeyAuthenticator("test-key", "test-client")

	var capturedClientID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClientID = GetClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	authHandler := Auth(mockAuth)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set(APIKeyHeader, "test-key")
	req.Header.Set(ClientIDHeader, "test-client")

	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)

	if capturedClientID != "test-client" {
		t.Errorf("expected client ID %q, got %q", "test-client", capturedClientID)
	}
}
