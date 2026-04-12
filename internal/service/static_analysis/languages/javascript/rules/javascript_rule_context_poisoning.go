package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSContextPoisoningRule detects context manipulation attacks in JS/TS.
// Based on MCP Attack Taxonomy: Context manipulation and shared state attacks.
type JSContextPoisoningRule struct{}

func NewJSContextPoisoningRule() model.Rule { return &JSContextPoisoningRule{} }

func (r *JSContextPoisoningRule) ID() string               { return "MCP-JS-CTX-001" }
func (r *JSContextPoisoningRule) Description() string       { return "Detects potential context poisoning by modifying context/state using user-supplied data in JavaScript/TypeScript" }
func (r *JSContextPoisoningRule) AppliesToLanguage() string { return "javascript" }

var jsContextPoisoningPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{regexp.MustCompile(`(?i)context\s*\[.*\]\s*=.*input`), "Direct context modification with user input", model.SeverityCritical},
	{regexp.MustCompile(`(?i)(session|state|global|shared)\s*\[.*\]\s*=`), "Shared state modification — potential context poisoning", model.SeverityHigh},
	{regexp.MustCompile(`(?i)(context|session|state)\.(set|assign|merge|update)\s*\(`), "Context bulk update — verify input sanitization", model.SeverityMedium},
	{regexp.MustCompile(`(?i)globalThis\s*\[`), "globalThis modification — global namespace poisoning", model.SeverityCritical},
	{regexp.MustCompile(`(?i)global\s*\[`), "Node global modification — namespace poisoning", model.SeverityCritical},
	{regexp.MustCompile(`(?i)window\s*\[`), "window object modification — namespace poisoning", model.SeverityHigh},
	{regexp.MustCompile(`(?i)Object\.defineProperty\s*\(`), "Object.defineProperty — potential property injection", model.SeverityMedium},
	{regexp.MustCompile(`(?i)Reflect\.(set|defineProperty)\s*\(`), "Reflect API modification — potential context poisoning", model.SeverityHigh},
}

func (r *JSContextPoisoningRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSContextPoisoningRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	if nodeType == "assignment_expression" || nodeType == "expression_statement" || nodeType == "call_expression" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range jsContextPoisoningPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}

		// Check for context + input combination
		if strings.Contains(text, "context") && strings.Contains(text, "input") {
			*findings = append(*findings, model.Finding{
				RuleID:   r.ID(),
				Message:  "Context modification with user input detected",
				Line:     int(node.StartPoint().Row) + 1,
				Snippet:  truncateSnippet(text, 200),
				Severity: model.SeverityHigh,
			})
		}
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSContextPoisoningRule())
}
