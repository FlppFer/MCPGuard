package rules

import (
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSCommandInjectionRule detects command injection vulnerabilities in JavaScript/TypeScript MCP servers.
type JSCommandInjectionRule struct{}

func NewJSCommandInjectionRule() model.Rule {
	return &JSCommandInjectionRule{}
}

func (r *JSCommandInjectionRule) ID() string          { return "MCP-JS-CMD-001" }
func (r *JSCommandInjectionRule) Description() string  { return "Detects command injection vulnerabilities in JavaScript/TypeScript" }
func (r *JSCommandInjectionRule) AppliesToLanguage() string { return "javascript" }

// Dangerous functions/methods for command execution
var jsDangerousFunctions = map[string]struct {
	description string
	severity    string
}{
	"exec":     {"child_process.exec — shell command execution", model.SeverityCritical},
	"execSync": {"child_process.execSync — synchronous shell command execution", model.SeverityCritical},
	"eval":     {"eval() — dynamic code evaluation", model.SeverityCritical},
	"Function": {"Function constructor — dynamic code generation", model.SeverityHigh},
}

func (r *JSCommandInjectionRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSCommandInjectionRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	if nodeType == "call_expression" {
		r.checkCallExpression(node, source, findings)
	}

	if nodeType == "new_expression" {
		r.checkNewExpression(node, source, findings)
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func (r *JSCommandInjectionRule) checkCallExpression(node *sitter.Node, source []byte, findings *[]model.Finding) {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil {
		return
	}
	funcText := string(source[funcNode.StartByte():funcNode.EndByte()])

	// Direct call: exec(...), eval(...), execSync(...)
	if info, ok := jsDangerousFunctions[funcText]; ok {
		*findings = append(*findings, model.Finding{
			RuleID:   r.ID(),
			Message:  info.description,
			Line:     int(node.StartPoint().Row) + 1,
			Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
			Severity: info.severity,
		})
	}

	// Member expression: cp.exec(...), child_process.execSync(...)
	if funcNode.Type() == "member_expression" {
		prop := funcNode.ChildByFieldName("property")
		if prop != nil {
			propName := string(source[prop.StartByte():prop.EndByte()])
			if info, ok := jsDangerousFunctions[propName]; ok {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  info.description + " (member call: " + funcText + ")",
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
					Severity: info.severity,
				})
			}
		}
	}

	// require('child_process')
	if funcText == "require" {
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
			if strings.Contains(argsText, "child_process") {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  "Import of child_process module — potential command execution",
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
					Severity: model.SeverityMedium,
				})
			}
		}
	}
}

func (r *JSCommandInjectionRule) checkNewExpression(node *sitter.Node, source []byte, findings *[]model.Finding) {
	constructor := node.ChildByFieldName("constructor")
	if constructor == nil {
		return
	}
	name := string(source[constructor.StartByte():constructor.EndByte()])
	if name == "Function" {
		*findings = append(*findings, model.Finding{
			RuleID:   r.ID(),
			Message:  "new Function() — dynamic code generation",
			Line:     int(node.StartPoint().Row) + 1,
			Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
			Severity: model.SeverityHigh,
		})
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
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSCommandInjectionRule())
}
