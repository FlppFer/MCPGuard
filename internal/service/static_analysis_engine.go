package service

import (
	"context"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
)

type StaticAnalysisService interface {
	// Analyze runs a single file analysis
	Analyze(language, filePath string, ast interface{}) ([]static_analysis_engine.Finding, error)
	// RunAnalysis runs analysis on all parsed files and returns results directly
	RunAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) (*static_analysis_engine.AnalysisResult, error)
}
