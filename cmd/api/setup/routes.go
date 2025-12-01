package setup

import (
	"log/slog"
	"net/http"

	middleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	"github.com/go-chi/chi/v5"
)

func InitRoutes(resources *Resources) {
	slog.Info("Initializing routes")

	r := chi.NewRouter()

	r.Route("/v1", func(r chi.Router) {
		// Webhook endpoints require GitHub signature verification
		r.Group(func(r chi.Router) {
			r.Use(middleware.WebhookAuth(resources.WebhookAuthenticator))
			r.Post("/webhook/github", resources.GitWebhookController.StartAnalysis())
		})

		// API endpoints require API key authentication
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(resources.APIKeyAuthenticator))
			r.Post("/analysis", resources.GitWebhookController.StartAnalysis())
			r.Get("/analysis/{id}/status", resources.GitWebhookController.GetAnalysisStatus())
			r.Get("/analysis/{id}/result", resources.GitWebhookController.GetAnalysisResult())
			r.Post("/agentic_analysis", resources.AgenticAnalysisController.RequestAgenticAnalysis())
		})
	})

	// Health check endpoint (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	slog.Info("Starting HTTP server", "port", 8080)
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}
}
