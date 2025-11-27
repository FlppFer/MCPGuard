package http

// WebHookRequestDTO represents the incoming webhook payload
type WebHookRequestDTO struct {
	RepoURL string `json:"repo_url"`
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit,omitempty"`
}
