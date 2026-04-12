package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSIndirectInjectionRule detects indirect tool injection attack patterns in JS/TS.
// Based on MCP Attack Taxonomy: Indirect Tool Injection Attack (III-B).
type JSIndirectInjectionRule struct{}

func NewJSIndirectInjectionRule() model.Rule { return &JSIndirectInjectionRule{} }

func (r *JSIndirectInjectionRule) ID() string               { return "MCP-JS-ITI-001" }
func (r *JSIndirectInjectionRule) Description() string       { return "Detects indirect tool injection via external data sources in JavaScript/TypeScript" }
func (r *JSIndirectInjectionRule) AppliesToLanguage() string { return "javascript" }

var jsIndirectInjectionPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-B1: Webpage Poison Attack
	{regexp.MustCompile(`(?i)(cheerio|jsdom|htmlparser2|DOMParser)`), "HTML parsing library — verify input sanitization for webpage poison attacks", model.SeverityMedium, "WEBPAGE-POISON"},
	{regexp.MustCompile(`(?i)<!--[^>]*-->`), "HTML comment detected — potential hidden instruction vector", model.SeverityMedium, "WEBPAGE-POISON"},
	{regexp.MustCompile(`(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>`), "Script tag in content — potential XSS/injection", model.SeverityHigh, "WEBPAGE-POISON"},
	{regexp.MustCompile(`(?i)style\s*=\s*['"]display\s*:\s*none`), "Hidden HTML element — potential concealed instructions", model.SeverityHigh, "WEBPAGE-POISON"},
	{regexp.MustCompile(`(?i)visibility\s*:\s*hidden`), "Hidden content via CSS — concealed instruction vector", model.SeverityHigh, "WEBPAGE-POISON"},
	{regexp.MustCompile(`(?i)innerHTML\s*=`), "innerHTML assignment — potential XSS injection vector", model.SeverityHigh, "WEBPAGE-POISON"},

	// III-B2: Malicious Project Installation Attack
	{regexp.MustCompile(`(?i)npm\s+install\s+git\+`), "npm install from git — verify repository trust", model.SeverityHigh, "MALICIOUS-PROJECT"},
	{regexp.MustCompile(`(?i)(child_process|exec|execSync).*npm\s+install`), "Dynamic package installation — potential supply chain attack", model.SeverityHigh, "MALICIOUS-PROJECT"},
	{regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh|node)`), "Curl pipe to interpreter — supply chain attack", model.SeverityCritical, "MALICIOUS-PROJECT"},
	{regexp.MustCompile(`(?i)(preinstall|postinstall|prepare)\s*['":]`), "npm lifecycle script — potential malicious install hook", model.SeverityHigh, "MALICIOUS-PROJECT"},

	// III-B3: MCP Tool Return Attack
	{regexp.MustCompile(`(?i)return\s+['"]error:\s*(please|use|call|invoke|try)\s+`), "Tool return with instruction — return attack vector", model.SeverityHigh, "TOOL-RETURN"},
	{regexp.MustCompile(`(?i)return\s+['"][^'"]*\b(admin_tool|verify|authenticate)\b`), "Tool return referencing other tools — return attack", model.SeverityHigh, "TOOL-RETURN"},
	{regexp.MustCompile(`(?i)return\s+.*\\x[0-9a-f]{2}`), "Hex-encoded content in return — obfuscated payload", model.SeverityHigh, "TOOL-RETURN"},
	{regexp.MustCompile(`(?i)return\s+['"].*execute\s+(this|the|following)`), "Return with execution instruction — return attack", model.SeverityCritical, "TOOL-RETURN"},

	// Deserialization
	{regexp.MustCompile(`(?i)JSON\.parse\s*\(\s*(req|request|input|body|params|query)`), "JSON.parse on user input — verify input validation", model.SeverityMedium, "DESERIALIZATION"},
	{regexp.MustCompile(`(?i)deserialize\s*\(`), "Deserialization call — verify input safety", model.SeverityHigh, "DESERIALIZATION"},
	{regexp.MustCompile(`(?i)yaml\.(load|parse)\s*\(`), "YAML parsing — verify safe loading", model.SeverityHigh, "DESERIALIZATION"},
}

// JS-specific dangerous deserialization functions
var jsDangerousDeserializationFuncs = map[string]string{
	"eval":           "eval() can execute arbitrary code from deserialized data",
	"Function":       "Function constructor can execute arbitrary code",
	"vm.runInContext": "vm.runInContext can execute arbitrary code in V8",
	"vm.runInNewContext": "vm.runInNewContext can execute arbitrary code in V8",
}

func (r *JSIndirectInjectionRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSIndirectInjectionRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	// Check for dangerous deserialization function calls
	if nodeType == "call_expression" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := string(source[funcNode.StartByte():funcNode.EndByte()])
			if desc, ok := jsDangerousDeserializationFuncs[funcName]; ok {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  desc,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
					Severity: model.SeverityCritical,
				})
			}
			// Member expression: vm.runInContext etc.
			if funcNode.Type() == "member_expression" {
				prop := funcNode.ChildByFieldName("property")
				if prop != nil {
					fullName := string(source[funcNode.StartByte():funcNode.EndByte()])
					if desc, ok := jsDangerousDeserializationFuncs[fullName]; ok {
						*findings = append(*findings, model.Finding{
							RuleID:   r.ID(),
							Message:  desc,
							Line:     int(node.StartPoint().Row) + 1,
							Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
							Severity: model.SeverityCritical,
						})
					}
				}
			}
		}
	}

	// Check for indirect injection patterns in strings and expressions
	if nodeType == "string" || nodeType == "template_string" || nodeType == "expression_statement" || nodeType == "call_expression" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsIndirectInjectionPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID() + "-" + p.attackID,
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}
	}

	// Check for innerHTML assignment (DOM-based injection)
	if nodeType == "assignment_expression" {
		text := string(source[node.StartByte():node.EndByte()])
		if strings.Contains(text, "innerHTML") {
			*findings = append(*findings, model.Finding{
				RuleID:   r.ID() + "-WEBPAGE-POISON",
				Message:  "innerHTML assignment — DOM-based injection risk",
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
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSIndirectInjectionRule())
}
