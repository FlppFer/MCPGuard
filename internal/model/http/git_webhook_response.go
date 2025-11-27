package http

import "time"

// WebHookResponseDTO represents the response after triggering analysis
type WebHookResponseDTO struct {
	AnalysisID string    `json:"analysis_id"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// ErrorResponseDTO represents an error response
type ErrorResponseDTO struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
