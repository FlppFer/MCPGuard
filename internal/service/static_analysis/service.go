package static_analysis

import (
	"context"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service/model"
)

// Service is the public interface for static code analysis.
// It orchestrates AST parsing, rule evaluation, and result aggregation.
type Service interface {
	// RunAnalysis processes all files and returns results directly.
	// This is the primary method used by external callers.
	RunAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) (*model.AnalysisResult, error)
}

// NewService creates a new static analysis service with the given options.
// The service is backed by an analysis engine that can be configured via functional options.
//
// Example:
//
//	service := NewService(
//	  WithOutputDir("/tmp/results"),
//	  WithPersistence(false),
//	)
func NewService(opts ...EngineOption) Service {
	return newEngine(opts...)
}
