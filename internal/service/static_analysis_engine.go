package service

import (
	"context"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
)

type StaticAnalysisService interface {
	// Analyze runs a single file analysis
	Analyze(language, filePath string, ast interface{}) ([]static_analysis_engine.Finding, error)
	// RunStaticAnalysis runs analysis on all parsed files for a given analysis ID
	RunStaticAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) error
}
