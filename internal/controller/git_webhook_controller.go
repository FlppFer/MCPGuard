package controller

import (
	"log/slog"
	"net/http"

	"github.com/FlppFer/MCPGuard/internal/service"
)

type GitWebhookControllerInterface interface {
	StartAnalysis() http.HandlerFunc
}

type gitWebhookController struct {
	gitWebhookServiceInterface service.GitWebhookService
}

func NewGitWebhookController(gitWebhookServiceInterface service.GitWebhookService) GitWebhookControllerInterface {
	return &gitWebhookController{
		gitWebhookServiceInterface: gitWebhookServiceInterface,
	}
}

func (g *gitWebhookController) StartAnalysis() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, err := w.Write([]byte("Hello world"))
		if err != nil {
			slog.Error(err.Error())
		}
		return
	}
}
