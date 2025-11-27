package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service"
)

type GitWebhookControllerInterface interface {
	StartAnalysis() http.HandlerFunc
	GetAnalysisStatus() http.HandlerFunc
}

type gitWebhookController struct {
	gitWebhookService service.GitWebhookService
}

func NewGitWebhookController(gitWebhookService service.GitWebhookService) GitWebhookControllerInterface {
	return &gitWebhookController{
		gitWebhookService: gitWebhookService,
	}
}

func (c *gitWebhookController) StartAnalysis() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req httpmodel.WebHookRequestDTO

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			c.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request body")
			return
		}

		if req.RepoURL == "" {
			c.writeError(w, http.StatusBadRequest, "missing_field", "repo_url is required")
			return
		}

		// Default branch to main if not specified
		if req.Branch == "" {
			req.Branch = "main"
		}

		result, err := c.gitWebhookService.RequestAnalysis(r.Context(), req.RepoURL, req.Branch, req.Commit)
		if err != nil {
			slog.Error("Failed to start analysis", "error", err)
			c.writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
			return
		}

		resp := httpmodel.WebHookResponseDTO{
			AnalysisID: result.AnalysisID,
			Status:     result.Status,
			Message:    "Analysis started successfully",
			Timestamp:  time.Now(),
		}

		c.writeJSON(w, http.StatusAccepted, resp)
	}
}

func (c *gitWebhookController) GetAnalysisStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement status check endpoint
		c.writeError(w, http.StatusNotImplemented, "not_implemented", "Status endpoint not yet implemented")
	}
}

func (c *gitWebhookController) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode response", "error", err)
	}
}

func (c *gitWebhookController) writeError(w http.ResponseWriter, status int, errCode, message string) {
	resp := httpmodel.ErrorResponseDTO{
		Error:   errCode,
		Message: message,
	}
	c.writeJSON(w, status, resp)
}
