package setup

import (
	"log/slog"
	"net/http"

	"github.com/FlppFer/MCPGuard/internal/middleware"
	"github.com/FlppFer/MCPGuard/internal/service"
	"github.com/go-chi/chi/v5"
)

func InitRoutes(secretsSvc service.SecretsService, resources *Resources) {
	slog.Info("Initializing routes")

	r := chi.NewRouter()

	// Apply API key auth middleware
	r.Use(middleware.APIKeyAuth(secretsSvc))

	// Git webhook entrypoint exposes StartAnalysis(w, r) so we can use it directly as an http.HandlerFunc
	r.Route("/v1", func(r chi.Router) {
		r.Post("/security_analysis", resources.GitWebhookController.StartAnalysis())
		r.Get("/security_analysis/{id}", resources.GitWebhookController.GetAnalysisStatus())
		r.Get("/security_analysis/{id}/result", resources.GitWebhookController.GetAnalysisResult())
		r.Post("/agentic_analysis", resources.AgenticAnalysisController.RequestAgenticAnalysis())
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
