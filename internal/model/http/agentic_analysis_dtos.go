package http

import "time"

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents the LLM's confidence in a finding (0.0–1.0).
type Confidence float64

const (
	ConfidenceNone Confidence = 0.0
	ConfidenceLow  Confidence = 0.25
	ConfidenceMid  Confidence = 0.50
	ConfidenceHigh Confidence = 0.75
	ConfidenceFull Confidence = 1.0
)

// StaticFindingContext is a condensed static finding passed as context to the agentic worker.
type StaticFindingContext struct {
	RuleID   string `json:"rule_id"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// AgenticAnalysisRequestDTO is sent to the Python agentic worker to start analysis.
type AgenticAnalysisRequestDTO struct {
	AnalysisID     string                 `json:"analysis_id"`
	RepoURL        string                 `json:"repo_url"`
	Branch         string                 `json:"branch"`
	Commit         string                 `json:"commit"`
	SourceKey      string                 `json:"source_key"`       // S3 key for the zipped source archive
	StaticFindings []StaticFindingContext `json:"static_findings"`  // Optional: findings from static analysis
	PRChangedFiles []string               `json:"pr_changed_files"` // Optional: restrict analysis to these files
}

// AgenticAnalysisResultDTO is received from the Python worker after analysis completes.
type AgenticAnalysisResultDTO struct {
	AnalysisID string              `json:"analysis_id"`
	Findings   []AgenticFindingDTO `json:"findings"`
	Summary    string              `json:"summary"`
	ModelUsed  string              `json:"model_used,omitempty"` // e.g., "gpt-4", "claude-3"
	Timestamp  time.Time           `json:"timestamp"`
}

// AgenticFindingDTO represents a single finding from the AI-based semantic analysis.
type AgenticFindingDTO struct {
	Category    string     `json:"category"`    // e.g., "tool_poisoning", "data_exfiltration"
	Description string     `json:"description"` // Human-readable explanation
	FilePath    string     `json:"file_path"`
	StartLine   int        `json:"start_line,omitempty"`
	EndLine     int        `json:"end_line,omitempty"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Suggestion  string     `json:"suggestion"` // Recommended mitigation
}
