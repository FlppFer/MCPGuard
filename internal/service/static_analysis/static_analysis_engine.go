package static_analysis

import (
	"context"

	"github.com/FlppFer/MCPGuard/internal/model/services"
)

type StaticAnalysisService interface {
	// Analyze runs a single file analysis
	Analyze(language, filePath string, ast interface{}) ([]Finding, error)
	// RunAnalysis runs analysis on all parsed files and returns results directly
	RunAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) (*AnalysisResult, error)
}
