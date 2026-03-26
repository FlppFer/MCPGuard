package services

import (
	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service/model"
)

// MergedAnalysisResultDTO combines static and agentic analysis findings.
type MergedAnalysisResultDTO struct {
	AnalysisID    string                              `json:"analysis_id"`
	Status        string                              `json:"status"`
	StaticResult  *model.AnalysisResult               `json:"static_result,omitempty"`
	AgenticResult *httpmodel.AgenticAnalysisResultDTO `json:"agentic_result,omitempty"`
}
