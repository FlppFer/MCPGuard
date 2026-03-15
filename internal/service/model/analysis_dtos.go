package model

// AnalysisResult holds all findings for a single analysis run
type AnalysisResult struct {
	AnalysisID string    `json:"analysis_id"`
	Files      int       `json:"files_analyzed"`
	Findings   []Finding `json:"findings"`
}

// Finding represents a single security issue detected by a rule
type Finding struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

// Severity constants for findings
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)
