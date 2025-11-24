package service

import "github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"

type StaticAnalysisService interface {
	Analyze(language, filePath string, ast interface{}) ([]static_analysis_engine.Finding, error)
}
