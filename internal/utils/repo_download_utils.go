package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/google/uuid"
)

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

	// Clone whole repo (shallow)
	cloneCmd := exec.Command("git", "clone", "--depth", "1", repoURL, repoDir)
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
