package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/google/uuid"
)

// injectGitToken rewrites an HTTPS GitHub URL to include a token from
// the GIT_AUTH_TOKEN env var, enabling cloning of private repositories.
// If the env var is empty or the URL is not HTTPS, the URL is returned unchanged.
func injectGitToken(repoURL string) string {
	token := os.Getenv("GIT_AUTH_TOKEN")
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

	// Clone whole repo (shallow)
	cloneCmd := exec.Command("git", "clone", "--depth", "1", cloneURL, repoDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr

	if err := cloneCmd.Run(); err != nil {
		return nil, fmt.Errorf("git clone failed: %w", err)
	}

	// Optionally checkout a commit or branch
	if commit != "" {
		checkoutCmd := exec.Command("git", "checkout", commit)
		checkoutCmd.Dir = repoDir
		if err := checkoutCmd.Run(); err != nil {
			return nil, fmt.Errorf("git checkout failed: %w", err)
		}
	} else if branch != "" {
		checkoutCmd := exec.Command("git", "checkout", branch)
		checkoutCmd.Dir = repoDir
		_ = checkoutCmd.Run() // optional, maybe no branch
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
