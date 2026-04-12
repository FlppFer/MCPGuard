package setup

import (
	"log/slog"
	"net/http"

	customMiddleware "github.com/FlppFer/MCPGuard/internal/middleware"
	authMiddleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter builds and returns the configured chi.Mux (does NOT start serving).
func NewRouter(resources *Resources) *chi.Mux {
	slog.Info("Initializing routes")

	r := chi.NewRouter()
	r.Use(customMiddleware.RequestID)
	r.Use(customMiddleware.PrometheusHTTP)

	r.Route("/v1", func(r chi.Router) {
		// Webhook endpoints require GitHub signature verification
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.WebhookAuth(resources.WebhookAuthenticator))
			r.Post("/webhook/github", resources.GitWebhookController.HandleGitHubWebhook())
		})

		// API endpoints require API key authentication
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Auth(resources.APIKeyAuthenticator))
			r.Post("/analysis", resources.GitWebhookController.StartAnalysis())
			r.Get("/analysis/{id}/status", resources.GitWebhookController.GetAnalysisStatus())
			r.Get("/analysis/{id}/result", resources.GitWebhookController.GetAnalysisResult())
			r.Get("/analysis/{id}/result/full", resources.GitWebhookController.GetMergedResult())
			r.Post("/agentic_analysis", resources.AgenticAnalysisController.ReceiveAgenticResult())
			r.Get("/agentic_analysis/{id}/result", resources.AgenticAnalysisController.GetAgenticResult())
		})
	})

	// Health check endpoint (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Prometheus metrics endpoint (no auth required)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	return r
}
