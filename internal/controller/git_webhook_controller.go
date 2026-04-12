package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	authMiddleware "github.com/FlppFer/MCPGuard/internal/middleware/auth"
	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service"
)

type GitWebhookControllerInterface interface {
	StartAnalysis() http.HandlerFunc
	HandleGitHubWebhook() http.HandlerFunc
	GetAnalysisStatus() http.HandlerFunc
	GetAnalysisResult() http.HandlerFunc
	GetMergedResult() http.HandlerFunc
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
			c.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, MsgFailedParseBody)
			return
		}

		if req.RepoURL == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingField, MsgRepoURLRequired)
			return
		}

		// Default branch to main if not specified
		if req.Branch == "" {
			req.Branch = MsgDefaultBranch
		}

		result, err := c.gitWebhookService.RequestAnalysis(r.Context(), req.RepoURL, req.Branch, req.Commit)
		if err != nil {
			slog.Error("Failed to start analysis", "error", err)
			c.writeError(w, http.StatusInternalServerError, ErrCodeAnalysisFailed, err.Error())
			return
		}

		resp := httpmodel.WebHookResponseDTO{
			AnalysisID: result.AnalysisID,
			Status:     result.Status,
			Message:    MsgAnalysisStarted,
			Timestamp:  time.Now(),
		}

		c.writeJSON(w, http.StatusAccepted, resp)
	}
}

// HandleGitHubWebhook routes GitHub webhook events by X-GitHub-Event header.
func (c *gitWebhookController) HandleGitHubWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		event := authMiddleware.GetGitHubEventFromContext(r.Context())

		switch event {
		case "push":
			c.handlePushEvent(w, r)
		case "pull_request":
			c.handlePullRequestEvent(w, r)
		default:
			c.writeJSON(w, http.StatusOK, map[string]string{
				"status":  "ignored",
				"message": fmt.Sprintf("Event type '%s' not handled", event),
			})
		}
	}
}

func (c *gitWebhookController) handlePushEvent(w http.ResponseWriter, r *http.Request) {
	var payload httpmodel.GitHubPushPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Error("Failed to parse GitHub webhook payload", "error", err)
		c.writeError(w, http.StatusBadRequest, ErrCodeInvalidPayload, MsgFailedParsePayload)
		return
	}

	repoURL := payload.GetRepoURL()
	branch := payload.GetBranch()
	commit := payload.GetCommit()

	if repoURL == "" {
		c.writeError(w, http.StatusBadRequest, ErrCodeMissingField, MsgCloneURLRequired)
		return
	}

	slog.Info("Received GitHub push webhook",
		"repo", payload.Repository.FullName,
		"branch", branch,
		"commit", commit)

	result, err := c.gitWebhookService.RequestAnalysis(r.Context(), repoURL, branch, commit)
	if err != nil {
		slog.Error("Failed to start analysis from GitHub webhook", "error", err)
		c.writeError(w, http.StatusInternalServerError, ErrCodeAnalysisFailed, err.Error())
		return
	}

	resp := httpmodel.WebHookResponseDTO{
		AnalysisID: result.AnalysisID,
		Status:     result.Status,
		Message:    MsgAnalysisStarted,
		Timestamp:  time.Now(),
	}

	c.writeJSON(w, http.StatusAccepted, resp)
}

func (c *gitWebhookController) handlePullRequestEvent(w http.ResponseWriter, r *http.Request) {
	var payload httpmodel.GitHubPullRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		c.writeError(w, http.StatusBadRequest, ErrCodeInvalidPayload, MsgFailedParsePayload)
		return
	}

	switch payload.Action {
	case "opened", "synchronize", "reopened":
		// proceed
	default:
		c.writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "action": payload.Action})
		return
	}

	repoURL := payload.Repository.CloneURL
	branch := payload.PullRequest.Head.Ref
	commit := payload.PullRequest.Head.SHA

	if repoURL == "" {
		c.writeError(w, http.StatusBadRequest, ErrCodeMissingField, MsgCloneURLRequired)
		return
	}

	slog.Info("Received GitHub pull_request webhook",
		"repo", payload.Repository.FullName,
		"pr", payload.Number,
		"branch", branch,
		"action", payload.Action)

	result, err := c.gitWebhookService.RequestAnalysisWithPR(r.Context(),
		repoURL, branch, commit, payload.Number, payload.Repository.FullName)
	if err != nil {
		slog.Error("Failed to start analysis from PR webhook", "error", err)
		c.writeError(w, http.StatusInternalServerError, ErrCodeAnalysisFailed, err.Error())
		return
	}

	resp := httpmodel.WebHookResponseDTO{
		AnalysisID: result.AnalysisID,
		Status:     result.Status,
		Message:    MsgAnalysisStarted,
		Timestamp:  time.Now(),
	}

	c.writeJSON(w, http.StatusAccepted, resp)
}

func (c *gitWebhookController) GetAnalysisStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		analysisID := chi.URLParam(r, "id")
		if analysisID == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingID, MsgIDRequired)
			return
		}

		status, err := c.gitWebhookService.GetAnalysisStatus(r.Context(), analysisID)
		if err != nil {
			slog.Error("Failed to get analysis status", "error", err, "analysis_id", analysisID)
			if errors.Is(err, service.ErrAnalysisNotFound) {
				c.writeError(w, http.StatusNotFound, ErrCodeNotFound, err.Error())
			} else {
				c.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}

		c.writeJSON(w, http.StatusOK, status)
	}
}

func (c *gitWebhookController) GetAnalysisResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		analysisID := chi.URLParam(r, "id")
		if analysisID == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingID, MsgIDRequired)
			return
		}

		data, err := c.gitWebhookService.GetAnalysisResult(r.Context(), analysisID)
		if err != nil {
			slog.Error("Failed to get analysis result", "error", err, "analysis_id", analysisID)
			if errors.Is(err, service.ErrAnalysisNotComplete) {
				c.writeError(w, http.StatusAccepted, ErrCodeAnalysisPending, err.Error())
			} else if errors.Is(err, service.ErrAnalysisNotFound) {
				c.writeError(w, http.StatusNotFound, ErrCodeNotFound, err.Error())
			} else {
				c.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}

		// Return raw JSON result
		w.Header().Set("Content-Type", ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// GetMergedResult handles GET /v1/analysis/{id}/result/full — returns combined static + agentic findings.
func (c *gitWebhookController) GetMergedResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		analysisID := chi.URLParam(r, "id")
		if analysisID == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingID, MsgIDRequired)
			return
		}

		merged, err := c.gitWebhookService.GetMergedResult(r.Context(), analysisID)
		if err != nil {
			slog.Error("Failed to get merged result", "error", err, "analysis_id", analysisID)
			if errors.Is(err, service.ErrAnalysisNotComplete) {
				c.writeError(w, http.StatusAccepted, ErrCodeAnalysisPending, err.Error())
			} else if errors.Is(err, service.ErrAnalysisNotFound) {
				c.writeError(w, http.StatusNotFound, ErrCodeNotFound, err.Error())
			} else {
				c.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}

		c.writeJSON(w, http.StatusOK, merged)
	}
}

func (c *gitWebhookController) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", ContentTypeJSON)
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
