package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service"
)

// mockSecretsService implements service.SecretsService for testing
type mockSecretsService struct {
	keys    map[string]string // apiKey -> clientID
	enabled bool
}

func (m *mockSecretsService) ValidateAPIKey(apiKey string) (string, bool) {
	clientID, exists := m.keys[apiKey]
	return clientID, exists
}

func (m *mockSecretsService) GetClientID(apiKey string) string {
	return m.keys[apiKey]
}

func (m *mockSecretsService) IsEnabled() bool {
	return m.enabled
}

func newMockSecretsService(keys map[string]string, enabled bool) service.SecretsService {
	return &mockSecretsService{keys: keys, enabled: enabled}
}

func TestAPIKeyAuth(t *testing.T) {
	mockSvc := newMockSecretsService(map[string]string{
		"test-key-1": "client-1",
		"test-key-2": "client-2",
	}, true)

	tests := []struct {
		name           string
		apiKey         string
		clientID       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid key and client",
			apiKey:         "test-key-1",
			clientID:       "client-1",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name:           "valid key 2 and client",
			apiKey:         "test-key-2",
			clientID:       "client-2",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name:           "valid key but wrong client",
			apiKey:         "test-key-1",
			clientID:       "wrong-client",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "client_mismatch",
		},
		{
			name:           "invalid key",
			apiKey:         "wrong-key",
			clientID:       "client-1",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid_api_key",
		},
		{
			name:           "missing api key",
			apiKey:         "",
			clientID:       "client-1",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "missing_api_key",
		},
		{
			name:           "missing client id",
			apiKey:         "test-key-1",
			clientID:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "missing_client_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			})

			authHandler := APIKeyAuth(mockSvc)(handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
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

func TestAPIKeyAuth_Disabled(t *testing.T) {
	// When auth is disabled, all requests should pass through
	mockSvc := newMockSecretsService(map[string]string{}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	authHandler := APIKeyAuth(mockSvc)(handler)

	// Request without any auth headers should pass
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestAPIKeyAuth_NoKeys(t *testing.T) {
	// When enabled but no keys configured, all requests should fail
	mockSvc := newMockSecretsService(map[string]string{}, true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := APIKeyAuth(mockSvc)(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(APIKeyHeader, "any-key")
	req.Header.Set(ClientIDHeader, "any-client")

	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestGetClientIDFromContext(t *testing.T) {
	mockSvc := newMockSecretsService(map[string]string{
		"test-key": "test-client",
	}, true)

	var capturedClientID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClientID = GetClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	authHandler := APIKeyAuth(mockSvc)(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(APIKeyHeader, "test-key")
	req.Header.Set(ClientIDHeader, "test-client")

	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)

	if capturedClientID != "test-client" {
		t.Errorf("expected client ID %q, got %q", "test-client", capturedClientID)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
