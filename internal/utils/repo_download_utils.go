package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FlppFer/MCPGuard/internal/metrics"
	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/google/uuid"
)

// injectGitToken rewrites an HTTPS GitHub URL to include a token from
// the GITHUB_TOKEN env var, enabling cloning of private repositories.
// If the env var is empty or the URL is not HTTPS, the URL is returned unchanged.
func injectGitToken(repoURL string) string {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return repoURL
	}
	if strings.HasPrefix(repoURL, "https://") {
		return strings.Replace(repoURL, "https://", "https://x-access-token:"+token+"@", 1)
	}
	return repoURL
}

func DownloadRepo(repoURL, branch, commit string) (*services.RepoDownloadResultDTO, error) {
	analysisID := uuid.NewString()
	baseDir := filepath.Join(os.TempDir(), "mcpguard", analysisID)
	repoDir := filepath.Join(baseDir, "repo")
	zipPath := filepath.Join(baseDir, "repo.zip")

	// Ensure base directory exists (but NOT repoDir - git clone needs it to not exist)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}

	// Remove repoDir if it exists (cleanup from previous failed attempt)
	_ = os.RemoveAll(repoDir)

	// Inject auth token for private repos if GIT_AUTH_TOKEN is set
	cloneURL := injectGitToken(repoURL)

	// Clone the specific branch (shallow). This ensures the commit from a PR branch is present.
	cloneArgs := []string{"clone", "--depth", "1"}
	if branch != "" {
		cloneArgs = append(cloneArgs, "--branch", branch)
	}
	cloneArgs = append(cloneArgs, cloneURL, repoDir)

	cloneCmd := exec.Command("git", cloneArgs...)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr

	cloneStart := time.Now()
	if err := cloneCmd.Run(); err != nil {
		metrics.RepoCloneErrors.Inc()
		return nil, fmt.Errorf("git clone failed: %w", err)
	}
	metrics.RepoCloneDuration.Observe(time.Since(cloneStart).Seconds())

	// Measure cloned repository size (best-effort — errors are non-fatal)
	if size, err := dirSize(repoDir); err == nil {
		metrics.RepoSizeBytes.Observe(float64(size))
	}

	// Zip the resulting folder
	if err := zipFolder(repoDir, zipPath); err != nil {
		return nil, fmt.Errorf("zip failed: %w", err)
	}

	return &services.RepoDownloadResultDTO{
		AnalysisID: analysisID,
		RepoURL:    repoURL,
		Branch:     branch,
		Commit:     commit,
		LocalPath:  repoDir,
		ZipPath:    zipPath,
	}, nil
}
