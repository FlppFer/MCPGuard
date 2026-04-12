package github_integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/FlppFer/MCPGuard/internal/service/model"
)

// PRCommentService posts analysis findings as comments on GitHub Pull Requests.
type PRCommentService interface {
	PostFindings(ctx context.Context, repoFullName string, prNumber int, result *model.AnalysisResult) error
}

type prCommentServiceImpl struct {
	githubToken string
	httpClient  *http.Client
	enabled     bool
}

func NewPRCommentService(githubToken string, enabled bool) PRCommentService {
	return &prCommentServiceImpl{
		githubToken: githubToken,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		enabled:     enabled,
	}
}

func (s *prCommentServiceImpl) PostFindings(ctx context.Context, repoFullName string, prNumber int, result *model.AnalysisResult) error {
	if !s.enabled {
		slog.Debug("GitHub PR comments disabled, skipping", "analysis_id", result.AnalysisID)
		return nil
	}

	body := FormatFindingsMarkdown(result)
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repoFullName, prNumber)

	payload, _ := json.Marshal(map[string]string{"body": body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create GitHub API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	slog.Info("Posted PR comment", "repo", repoFullName, "pr", prNumber, "findings", len(result.Findings))
	return nil
}
