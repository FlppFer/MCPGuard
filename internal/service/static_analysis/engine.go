package static_analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

// engine is the internal implementation of the Service interface.
// It manages rule execution, AST parsing, and result persistence.
type engine struct {
	outputDir      string
	persistResults bool
}

// EngineOption is a functional option for configuring the analysis engine
type EngineOption func(*engine)

// WithOutputDir sets a custom output directory for analysis results
func WithOutputDir(dir string) EngineOption {
	return func(e *engine) {
		e.outputDir = dir
	}
}

// WithPersistence enables or disables saving results to disk
func WithPersistence(persist bool) EngineOption {
	return func(e *engine) {
		e.persistResults = persist
	}
}

// newEngine creates a new analysis engine with the given options.
// This is an internal constructor - external callers should use NewService().
func newEngine(opts ...EngineOption) *engine {
	e := &engine{
		outputDir:      "./analysis_results",
		persistResults: true,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// RunAnalysis processes all files and returns results directly.
// This implements the Service interface.
func (e *engine) RunAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) (*model.AnalysisResult, error) {
	slog.Info("Starting static analysis", "analysis_id", analysisID, "file_count", len(files))

	var allFindings []model.Finding

	for _, file := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Parse AST based on language
		ast, err := e.parseAST(file)
		if err != nil {
			slog.Warn("Failed to parse file", "path", file.Path, "error", err)
			continue
		}

		// Run rules against the AST
		findings, err := e.analyze(file.Language, file.Path, ast)
		if err != nil {
			slog.Warn("Analysis failed for file", "path", file.Path, "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	result := &model.AnalysisResult{
		AnalysisID: analysisID,
		Files:      len(files),
		Findings:   allFindings,
	}

	// Optionally persist results to disk
	if e.persistResults {
		if err := e.saveResults(analysisID, *result); err != nil {
			return nil, fmt.Errorf("failed to save analysis results: %w", err)
		}
	}

	slog.Info("Static analysis completed", "analysis_id", analysisID, "findings", len(allFindings))
	return result, nil
}

// parseAST parses the source file into an AST based on its language
func (e *engine) parseAST(file services.SourceFileDTO) (interface{}, error) {
	switch file.Language {
	case LanguagePython:
		return python.ParsePythonSource(file.Path, []byte(file.Content))
	default:
		// For unsupported languages, return nil AST (rules may work with raw content)
		return nil, nil
	}
}

// analyze runs all registered rules for a given language against the AST
func (e *engine) analyze(language, filePath string, ast interface{}) ([]model.Finding, error) {
	rules := GetRules(language)

	var findings []model.Finding

	for _, rule := range rules {
		f, err := rule.Evaluate(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %s failed: %w", rule.ID(), err)
		}

		// Set file path on each finding
		for i := range f {
			f[i].FilePath = filePath
		}
		findings = append(findings, f...)
	}

	return findings, nil
}

// saveResults persists analysis results to disk as JSON
func (e *engine) saveResults(analysisID string, result model.AnalysisResult) error {
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

// LoadAnalysisResult loads a previously saved analysis result by ID.
// This is a utility method for retrieving persisted results.
func (e *engine) LoadAnalysisResult(analysisID string) (*model.AnalysisResult, error) {
	filePath := filepath.Join(e.outputDir, fmt.Sprintf("%s_static.json", analysisID))
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var result model.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
