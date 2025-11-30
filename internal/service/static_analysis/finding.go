package static_analysis

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
