package http

import "strings"

// WebHookRequestDTO represents the incoming webhook payload (manual API call)
type WebHookRequestDTO struct {
	RepoURL string `json:"repo_url"`
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// GitHubPushPayload represents the GitHub push event webhook payload
type GitHubPushPayload struct {
	Ref        string `json:"ref"`    // e.g., "refs/heads/main"
	After      string `json:"after"`  // commit SHA after push
	Before     string `json:"before"` // commit SHA before push
	Repository struct {
		CloneURL string `json:"clone_url"` // e.g., "https://github.com/user/repo.git"
		FullName string `json:"full_name"` // e.g., "user/repo"
		Private  bool   `json:"private"`
	} `json:"repository"`
	HeadCommit *struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"head_commit"`
}

// GetBranch extracts the branch name from the ref (e.g., "refs/heads/main" -> "main")
func (p *GitHubPushPayload) GetBranch() string {
	const prefix = "refs/heads/"
	if strings.HasPrefix(p.Ref, prefix) {
		return strings.TrimPrefix(p.Ref, prefix)
	}
	return p.Ref
}

// GetCommit returns the commit SHA (after push)
func (p *GitHubPushPayload) GetCommit() string {
	return p.After
}

// GetRepoURL returns the clone URL
func (p *GitHubPushPayload) GetRepoURL() string {
	return p.Repository.CloneURL
}

// GitHubPullRequestPayload represents the GitHub pull_request event webhook payload.
type GitHubPullRequestPayload struct {
	Action      string `json:"action"` // "opened", "synchronize", "reopened", "closed", etc.
	Number      int    `json:"number"` // PR number
	PullRequest struct {
		Head struct {
			Ref string `json:"ref"` // branch name
			SHA string `json:"sha"` // commit SHA
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		CloneURL string `json:"clone_url"`
		FullName string `json:"full_name"` // "owner/repo"
	} `json:"repository"`
}
