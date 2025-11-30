package setup

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func InitRoutes(resources *Resources) {
	slog.Info("Initializing routes")

	r := chi.NewRouter()
	//TODO implement common middleware logger
	//r.Use()

	// Git webhook entrypoint exposes StartAnalysis(w, r) so we can use it directly as an http.HandlerFunc
	r.Route("/v1", func(r chi.Router) {
		r.Post("/security_analysis", resources.GitWebhookController.StartAnalysis())
		r.Get("/security_analysis/{id}", resources.GitWebhookController.GetAnalysisStatus())
		r.Get("/security_analysis/{id}/result", resources.GitWebhookController.GetAnalysisResult())
		r.Post("/agentic_analysis", resources.AgenticAnalysisController.RequestAgenticAnalysis())
	})

	err := http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}

}
