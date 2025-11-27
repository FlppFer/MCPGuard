package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
)

type (
	AgenticAnalysisControllerInterface interface {
		RequestAgenticAnalysis() http.HandlerFunc
	}

	agenticAnalysisController struct{}
)

func NewAgenticAnalysisController() AgenticAnalysisControllerInterface {
	return &agenticAnalysisController{}
}

func (c *agenticAnalysisController) RequestAgenticAnalysis() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This endpoint will be called by the Python agentic worker
		// to submit analysis results back to the Go orchestrator
		c.writeError(w, http.StatusNotImplemented, "not_implemented", "Agentic analysis endpoint not yet implemented")
	}
}

func (c *agenticAnalysisController) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode response", "error", err)
	}
}

func (c *agenticAnalysisController) writeError(w http.ResponseWriter, status int, errCode, message string) {
	resp := httpmodel.ErrorResponseDTO{
		Error:   errCode,
		Message: message,
	}
	c.writeJSON(w, status, resp)
}
