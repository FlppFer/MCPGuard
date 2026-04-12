package messaging

// Queue name constants.
const (
	QueueStaticAnalysis  = "mcpguard.static_analysis"
	QueueAgenticAnalysis = "mcpguard.agentic_analysis"
)

// AnalysisJobMessage is published to the static analysis queue.
type AnalysisJobMessage struct {
	AnalysisID string `json:"analysis_id"`
	RepoURL    string `json:"repo_url"`
	Branch     string `json:"branch"`
	Commit     string `json:"commit"`
	SourceKey  string `json:"source_key"`
}
