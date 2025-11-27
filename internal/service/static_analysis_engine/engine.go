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
	outputDir      string
	persistResults bool
}

// EngineOption is a functional option for configuring the Engine
type EngineOption func(*Engine)

// WithOutputDir sets a custom output directory for analysis results
func WithOutputDir(dir string) EngineOption {
	return func(e *Engine) {
		e.outputDir = dir
	}
}

// WithPersistence enables or disables saving results to disk
func WithPersistence(persist bool) EngineOption {
	return func(e *Engine) {
		e.persistResults = persist
	}
}

func NewStaticAnalyzerEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		outputDir:      "./analysis_results",
		persistResults: true,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
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

	// Save results to file (if persistence is enabled)
	result := AnalysisResult{
		AnalysisID: analysisID,
		Files:      len(files),
		Findings:   allFindings,
	}

	if e.persistResults {
		if err := e.saveResults(analysisID, result); err != nil {
			return fmt.Errorf("failed to save analysis results: %w", err)
		}
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

// LoadAnalysisResult loads a previously saved analysis result by ID
func (e *Engine) LoadAnalysisResult(analysisID string) (*AnalysisResult, error) {
	filePath := filepath.Join(e.outputDir, fmt.Sprintf("%s_static.json", analysisID))
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var result AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RunAnalysis processes all files and returns results directly without persisting
// This is useful for testing or one-off analysis
func (e *Engine) RunAnalysis(ctx context.Context, analysisID string, files []services.SourceFileDTO) (*AnalysisResult, error) {
	var allFindings []Finding

	for _, file := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var ast interface{}
		if file.Language == LanguagePython {
			pyAST, err := python.ParsePythonSource(file.Path, []byte(file.Content))
			if err != nil {
				slog.Warn("Failed to parse Python file", "path", file.Path, "error", err)
				continue
			}
			ast = pyAST
		}

		findings, err := e.Analyze(file.Language, file.Path, ast)
		if err != nil {
			slog.Warn("Analysis failed for file", "path", file.Path, "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	result := &AnalysisResult{
		AnalysisID: analysisID,
		Files:      len(files),
		Findings:   allFindings,
	}

	if e.persistResults {
		if err := e.saveResults(analysisID, *result); err != nil {
			return nil, fmt.Errorf("failed to save analysis results: %w", err)
		}
	}

	return result, nil
}
