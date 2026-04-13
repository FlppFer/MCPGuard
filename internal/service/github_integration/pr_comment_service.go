package github_integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service/model"
)

// PRCommentService posts analysis findings as comments on GitHub Pull Requests.
type PRCommentService interface {
	PostFindings(ctx context.Context, repoFullName string, prNumber int, result *model.AnalysisResult) error
	PostAgenticFindings(ctx context.Context, repoFullName string, prNumber int, result *httpmodel.AgenticAnalysisResultDTO) error
	FetchChangedFiles(ctx context.Context, repoFullName string, prNumber int) ([]string, error)
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

func (s *prCommentServiceImpl) FetchChangedFiles(ctx context.Context, repoFullName string, prNumber int) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/pulls/%d/files", repoFullName, prNumber)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var files []struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub PR files response: %w", err)
	}

	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Filename)
	}
	slog.Info("Fetched PR changed files", "repo", repoFullName, "pr", prNumber, "count", len(paths))
	return paths, nil
}

func (s *prCommentServiceImpl) PostAgenticFindings(ctx context.Context, repoFullName string, prNumber int, result *httpmodel.AgenticAnalysisResultDTO) error {
	if !s.enabled {
		slog.Debug("GitHub PR comments disabled, skipping agentic comment", "analysis_id", result.AnalysisID)
		return nil
	}

	body := FormatAgenticFindingsMarkdown(result)
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

	slog.Info("Posted agentic PR comment", "repo", repoFullName, "pr", prNumber, "findings", len(result.Findings))
	return nil
}
