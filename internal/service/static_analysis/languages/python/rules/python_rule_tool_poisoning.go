package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// ToolPoisoningRule detects malicious instructions in tool descriptions and __doc__ attributes
// Based on MCP Attack Taxonomy: Direct Tool Injection Attack (III-A1)
// Covers: Rug Pull Attack (III-A1e), Tool Preference Manipulation
type ToolPoisoningRule struct{}

func NewToolPoisoningRule() model.Rule {
	return &ToolPoisoningRule{}
}

func (r *ToolPoisoningRule) ID() string {
	return "MCP-DTI-001-TOOL-POISON"
}

func (r *ToolPoisoningRule) Description() string {
	return "Detects potential tool poisoning via malicious instructions in tool descriptions or __doc__ attributes"
}

func (r *ToolPoisoningRule) AppliesToLanguage() string {
	return "python"
}

// Suspicious patterns that indicate tool poisoning attempts
var toolPoisoningPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// Rug Pull Attack (III-A1e) - Dynamic poisoning after trust established
	{
		pattern:     regexp.MustCompile(`(?i)(execute|run|call)\s+(this|the)\s+(code|command|script)\s+(before|after|first)`),
		description: "Instruction to execute code before/after tool execution",
		severity:    model.SeverityCritical,
		attackID:    "RUG-PULL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)ignore\s+(previous|all|other)\s+(instructions?|prompts?|rules?)`),
		description: "Attempt to override previous instructions",
		severity:    model.SeverityCritical,
		attackID:    "INSTRUCTION-OVERRIDE",
	},
	// Tool Preference Manipulation (III-A2b)
	{
		pattern:     regexp.MustCompile(`(?i)(do\s+not|don'?t|never)\s+(use|call|invoke)\s+(other|any|the)\s+tool`),
		description: "Instruction to prevent use of other tools",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-PREFERENCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(always|must|should)\s+(use|prefer|call)\s+this\s+tool`),
		description: "Forced tool preference manipulation",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-PREFERENCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(best\s+practice|recommended|preferred)\s+(tool|method|approach)`),
		description: "Tool preference manipulation via authority claims",
		severity:    model.SeverityMedium,
		attackID:    "TOOL-PREFERENCE",
	},
	// Malicious Tool Coverage Attack (III-A2b)
	{
		pattern:     regexp.MustCompile(`(?i)(deprecated|obsolete|old\s+version|replaced\s+by|unavailable)`),
		description: "Potential tool coverage attack claiming other tools are deprecated",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-COVERAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(original|old|previous)\s+(tool|version)\s+(is\s+)?(broken|buggy|insecure)`),
		description: "False claims about other tool's reliability",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-COVERAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(admin|root|sudo|superuser)\s+(mode|access|privilege)`),
		description: "Attempt to claim elevated privileges",
		severity:    model.SeverityHigh,
		attackID:    "PRIVILEGE-CLAIM",
	},
	// Dynamic __doc__ modification (Rug Pull vector)
	{
		pattern:     regexp.MustCompile(`(?i)__doc__\s*=`),
		description: "Dynamic __doc__ modification - rug pull attack vector",
		severity:    model.SeverityCritical,
		attackID:    "RUG-PULL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)setattr\s*\([^,]+,\s*['"]__doc__['"]`),
		description: "Dynamic docstring modification via setattr",
		severity:    model.SeverityCritical,
		attackID:    "RUG-PULL",
	},
}

func (r *ToolPoisoningRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding

	// Look for docstrings and string literals that might contain malicious instructions
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *ToolPoisoningRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check string literals and docstrings
	if nodeType == "string" || nodeType == "expression_statement" {
		text := source[node.StartByte():node.EndByte()]
		textStr := string(text)

		// Check for tool poisoning patterns
		for _, p := range toolPoisoningPatterns {
			if p.pattern.MatchString(textStr) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(textStr, 200),
					Severity: p.severity,
				})
			}
		}

		// Check for __doc__ attribute assignments
		if strings.Contains(textStr, "__doc__") {
			*findings = append(*findings, model.Finding{
				RuleID:   r.ID(),
				Message:  "Direct __doc__ attribute modification detected - potential rug pull attack vector",
				Line:     int(node.StartPoint().Row) + 1,
				Snippet:  truncateSnippet(textStr, 200),
				Severity: model.SeverityMedium,
			})
		}
	}

	// Check function definitions for suspicious docstrings
	if nodeType == "function_definition" {
		// Look for the docstring (first child that is an expression_statement with a string)
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			if child.Type() == "block" {
				for j := uint32(0); j < child.ChildCount(); j++ {
					blockChild := child.Child(int(j))
					if blockChild.Type() == "expression_statement" {
						exprChild := blockChild.Child(0)
						if exprChild != nil && exprChild.Type() == "string" {
							docstring := string(source[exprChild.StartByte():exprChild.EndByte()])
							for _, p := range toolPoisoningPatterns {
								if p.pattern.MatchString(docstring) {
									*findings = append(*findings, model.Finding{
										RuleID:   r.ID(),
										Message:  "Suspicious docstring: " + p.description,
										Line:     int(exprChild.StartPoint().Row) + 1,
										Snippet:  truncateSnippet(docstring, 200),
										Severity: p.severity,
									})
								}
							}
						}
						break // Only first statement can be docstring
					}
				}
			}
		}
	}

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewToolPoisoningRule())
}



