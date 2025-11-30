package services

import "time"

type GitWebhookAnalysisResultDTO struct {
	AnalysisID string
	Status     string
	Timestamp  time.Time
}

// AnalysisStatusDTO represents the current status of an analysis
type AnalysisStatusDTO struct {
	AnalysisID   string    `json:"analysis_id"`
	RepoURL      string    `json:"repo_url"`
	Branch       string    `json:"branch"`
	Commit       string    `json:"commit,omitempty"`
	Status       string    `json:"status"`
	ErrorMessage string    `json:"error_message,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
