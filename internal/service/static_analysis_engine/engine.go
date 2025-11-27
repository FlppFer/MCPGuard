package static_analysis_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
)

// AnalysisResult holds all findings for a single analysis run
type AnalysisResult struct {
	AnalysisID string    `json:"analysis_id"`
	Files      int       `json:"files_analyzed"`
	Findings   []Finding `json:"findings"`
}

type Engine struct {
	outputDir string
}

func NewStaticAnalyzerEngine() *Engine {
	return &Engine{
		outputDir: "./analysis_results",
	}
}

func (e *Engine) Analyze(language, filePath string, ast interface{}) ([]Finding, error) {
	rules := GetRules(language)

	var findings []Finding

	for _, rule := range rules {
		f, err := rule.Evaluate(ast)
		if err != nil {
			return nil, err
		}
		// Set file path on each finding
		for i := range f {
			f[i].FilePath = filePath
		}
		findings = append(findings, f...)
	}

	return findings, nil
}

// RunStaticAnalysis processes all files and stores results
func (e *Engine) RunStaticAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) error {
	slog.Info("Starting static analysis", "analysis_id", analysisID, "file_count", len(files))

	var allFindings []Finding

	for _, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Parse AST for Python files
		var ast interface{}
		if file.Language == LanguagePython {
			pyAST, err := python.ParsePythonSource(file.Path, []byte(file.Content))
			if err != nil {
				slog.Warn("Failed to parse Python file", "path", file.Path, "error", err)
				continue
			}
			ast = pyAST
		} else {
			// For non-Python files, pass nil AST (rules can work with content directly if needed)
			ast = nil
		}

		findings, err := e.Analyze(file.Language, file.Path, ast)
		if err != nil {
			slog.Warn("Analysis failed for file", "path", file.Path, "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	// Save results to file
	result := AnalysisResult{
		AnalysisID: analysisID,
		Files:      len(files),
		Findings:   allFindings,
	}

	if err := e.saveResults(analysisID, result); err != nil {
		return fmt.Errorf("failed to save analysis results: %w", err)
	}

	slog.Info("Static analysis completed", "analysis_id", analysisID, "findings", len(allFindings))
	return nil
}

func (e *Engine) saveResults(analysisID string, result AnalysisResult) error {
	if err := os.MkdirAll(e.outputDir, 0755); err != nil {
		return err
	}

	filePath := filepath.Join(e.outputDir, fmt.Sprintf("%s_static.json", analysisID))
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}