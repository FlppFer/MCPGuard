package static_analysis_engine

type ASTNode interface{}

type AnalysisResult struct {
	RuleName string
	FilePath string
	Message  string
	Line     int
}
