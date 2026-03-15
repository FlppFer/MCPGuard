# Task 6.1: PR Comment Service

| Field | Value |
|-------|-------|
| **ID** | task-6.1 |
| **Phase** | 6 — GitHub Actions PR Integration |
| **Priority** | Medium |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

The MCPGuard article describes automatically posting analysis findings as comments on GitHub Pull Requests. No such functionality exists — after analysis completes, results are only available via the REST API. Developers must manually check results instead of seeing them directly in their PR.

### Expected Behavior

1. After analysis completes (triggered by a PR event), MCPGuard posts a formatted Markdown comment on the Pull Request summarizing findings.
2. The comment includes: total findings count, a breakdown by severity, and a table of the top findings with file path, line, rule ID, and message.
3. If no findings are detected, a "clean" comment is posted.
4. The feature is gated behind a config flag (`github_integration.enabled`).

### Acceptance Criteria

- A PR comment is posted via the GitHub REST API after analysis of a PR-triggered webhook.
- The comment is well-formatted Markdown with severity breakdown and findings table.
- If the GitHub API call fails, the error is logged but does not fail the analysis.
- The feature can be disabled via config.

---

## Technical Specification

### GitHub REST API

**Endpoint:** `POST /repos/{owner}/{repo}/issues/{pr_number}/comments`
**Auth:** Bearer token (GitHub PAT or GitHub App installation token)
**Body:** `{ "body": "markdown content" }`

### Create `internal/service/github_integration/pr_comment_service.go`

```go
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
```

### Create `internal/service/github_integration/markdown_formatter.go`

```go
package github_integration

import (
    "fmt"
    "strings"

    "github.com/FlppFer/MCPGuard/internal/service/model"
)

func FormatFindingsMarkdown(result *model.AnalysisResult) string {
    var sb strings.Builder

    sb.WriteString("## 🔒 MCPGuard Security Analysis\n\n")
    sb.WriteString(fmt.Sprintf("**Analysis ID:** `%s`\n", result.AnalysisID))
    sb.WriteString(fmt.Sprintf("**Files analyzed:** %d\n", result.Files))
    sb.WriteString(fmt.Sprintf("**Total findings:** %d\n\n", len(result.Findings)))

    if len(result.Findings) == 0 {
        sb.WriteString("✅ No security issues detected.\n")
        return sb.String()
    }

    // Severity breakdown
    counts := map[string]int{}
    for _, f := range result.Findings {
        counts[f.Severity]++
    }
    sb.WriteString("### Severity Breakdown\n\n")
    for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
        if c, ok := counts[sev]; ok {
            sb.WriteString(fmt.Sprintf("- **%s:** %d\n", strings.ToUpper(sev), c))
        }
    }

    // Findings table (top 20)
    sb.WriteString("\n### Findings\n\n")
    sb.WriteString("| Severity | Rule | File | Line | Message |\n")
    sb.WriteString("|----------|------|------|------|---------|\n")
    limit := 20
    if len(result.Findings) < limit {
        limit = len(result.Findings)
    }
    for _, f := range result.Findings[:limit] {
        sb.WriteString(fmt.Sprintf("| %s | `%s` | `%s` | %d | %s |\n",
            f.Severity, f.RuleID, f.FilePath, f.Line, truncate(f.Message, 80)))
    }
    if len(result.Findings) > 20 {
        sb.WriteString(fmt.Sprintf("\n_...and %d more findings. See full results via the API._\n",
            len(result.Findings)-20))
    }

    return sb.String()
}

func truncate(s string, max int) string {
    if len(s) <= max {
        return s
    }
    return s[:max-3] + "..."
}
```

### Config Changes

**`config/config.go`:**
```go
type GitHubIntegrationConfig struct {
    Enabled     bool   `yaml:"enabled"`
    TokenEnvVar string `yaml:"token_env_var"` // Name of env var holding the GitHub token
}
```

Add `GitHubIntegrationCfg *GitHubIntegrationConfig \`yaml:"github_integration"\`` to `Config`.

**`config/default.yaml`:**
```yaml
github_integration:
  enabled: false
  token_env_var: "GITHUB_TOKEN"
```

**`config/prod.yaml`:**
```yaml
github_integration:
  enabled: true
  token_env_var: "GITHUB_TOKEN"
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/service/github_integration/pr_comment_service.go` | Service to post PR comments |
| `internal/service/github_integration/markdown_formatter.go` | Format findings as Markdown |

### Files to Modify

| File | Change |
|------|--------|
| `config/config.go` | Add `GitHubIntegrationConfig` |
| `config/default.yaml` | Add `github_integration` section |
| `config/prod.yaml` | Add `github_integration` section |

### Testing

- Unit test `FormatFindingsMarkdown` with 0 findings → contains "No security issues".
- Unit test with 5 findings → contains severity breakdown and table rows.
- Unit test with 25 findings → table limited to 20 + "and 5 more" message.
- Integration test with mock HTTP server → verify POST body is valid Markdown.
