package rules

import (
	"bytes"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
	ts "github.com/smacker/go-tree-sitter"
)

type ContextPoisoningRule struct{}

func NewContextPoisoningRule() static_analysis_engine.Rule {
	return &ContextPoisoningRule{}
}

func (r *ContextPoisoningRule) ID() string {
	return "PY-CON-001"
}

func (r *ContextPoisoningRule) Description() string {
	return "Detects potential context poisoning by modifying context variables using user-supplied data."
}

func (r *ContextPoisoningRule) AppliesToLanguage() string {
	return "python"
}

func (r *ContextPoisoningRule) Evaluate(ast interface{}) ([]static_analysis_engine.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	cursor := ts.NewTreeCursor(py.Tree.RootNode())

	var findings []static_analysis_engine.Finding

	// Traverse AST: Find assignments like "context[...] = user_input"
	for {
		node := cursor.CurrentNode()

		if node.Type() == "assignment" {
			text := py.Source[node.StartByte():node.EndByte()]

			if bytes.Contains(text, []byte("context")) && bytes.Contains(text, []byte("input")) {
				findings = append(findings, static_analysis_engine.Finding{
					RuleID:   r.ID(),
					Message:  r.Description(),
					FilePath: "", // you fill from caller
					Line:     int(node.StartPoint().Row),
					Snippet:  string(text),
					Severity: static_analysis_engine.SeverityHigh,
				})
			}
		}

		if !cursor.GoToNextSibling() {
			break
		}
	}

	return findings, nil
}

func init() {
	static_analysis_engine.RegisterRule(static_analysis_engine.LanguagePython, NewContextPoisoningRule())
}