package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// ContextPoisoningRule detects context manipulation attacks
// Based on MCP Attack Taxonomy: Context manipulation and shared state attacks
type ContextPoisoningRule struct{}

func NewContextPoisoningRule() static_analysis.Rule {
	return &ContextPoisoningRule{}
}

func (r *ContextPoisoningRule) ID() string {
	return "MCP-CTX-001"
}

func (r *ContextPoisoningRule) Description() string {
	return "Detects potential context poisoning by modifying context variables using user-supplied data"
}

func (r *ContextPoisoningRule) AppliesToLanguage() string {
	return "python"
}

// Context poisoning patterns
var contextPoisoningPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{
		pattern:     regexp.MustCompile(`(?i)context\s*\[.*\]\s*=.*input`),
		description: "Direct context modification with user input",
		severity:    static_analysis.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(session|state|global|shared)\s*\[.*\]\s*=`),
		description: "Shared state modification - potential context poisoning",
		severity:    static_analysis.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)setattr\s*\(\s*(context|session|state)`),
		description: "Dynamic attribute setting on context object",
		severity:    static_analysis.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(context|session|state)\.update\s*\(`),
		description: "Bulk context update - verify input sanitization",
		severity:    static_analysis.SeverityMedium,
	},
	{
		pattern:     regexp.MustCompile(`(?i)globals\s*\(\s*\)\s*\[`),
		description: "Global namespace modification",
		severity:    static_analysis.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)locals\s*\(\s*\)\s*\[`),
		description: "Local namespace modification",
		severity:    static_analysis.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)__dict__\s*\[.*\]\s*=`),
		description: "Direct __dict__ manipulation",
		severity:    static_analysis.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)vars\s*\(\s*\)\s*\[.*\]\s*=`),
		description: "vars() manipulation for context poisoning",
		severity:    static_analysis.SeverityHigh,
	},
}

func (r *ContextPoisoningRule) Evaluate(ast interface{}) ([]static_analysis.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []static_analysis.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *ContextPoisoningRule) walkTree(node *sitter.Node, source []byte, findings *[]static_analysis.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check assignments for context poisoning
	if nodeType == "assignment" || nodeType == "expression_statement" || nodeType == "call" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range contextPoisoningPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, static_analysis.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}

		// Check for context + input combination (original logic)
		if strings.Contains(text, "context") && strings.Contains(text, "input") {
			*findings = append(*findings, static_analysis.Finding{
				RuleID:   r.ID(),
				Message:  "Context modification with user input detected",
				Line:     int(node.StartPoint().Row) + 1,
				Snippet:  truncateSnippet(text, 200),
				Severity: static_analysis.SeverityHigh,
			})
		}
	}

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewContextPoisoningRule())
}
