package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSFileOperationsRule detects dangerous file system operations in JavaScript/TypeScript MCP servers.
type JSFileOperationsRule struct{}

func NewJSFileOperationsRule() model.Rule {
	return &JSFileOperationsRule{}
}

func (r *JSFileOperationsRule) ID() string               { return "MCP-JS-FS-001" }
func (r *JSFileOperationsRule) Description() string       { return "Detects dangerous file system operations in JavaScript/TypeScript" }
func (r *JSFileOperationsRule) AppliesToLanguage() string { return "javascript" }

// Dangerous fs methods
var jsDangerousFSMethods = map[string]struct {
	description string
	severity    string
}{
	"readFileSync":  {"fs.readFileSync — synchronous file read", model.SeverityMedium},
	"writeFileSync": {"fs.writeFileSync — synchronous file write", model.SeverityHigh},
	"unlinkSync":    {"fs.unlinkSync — synchronous file deletion", model.SeverityHigh},
	"rmdirSync":     {"fs.rmdirSync — synchronous directory removal", model.SeverityHigh},
	"chmodSync":     {"fs.chmodSync — permission modification", model.SeverityHigh},
	"chownSync":     {"fs.chownSync — ownership modification", model.SeverityHigh},
	"readFile":      {"fs.readFile/fs.promises.readFile — file read", model.SeverityMedium},
	"writeFile":     {"fs.writeFile/fs.promises.writeFile — file write", model.SeverityHigh},
	"unlink":        {"fs.unlink/fs.promises.unlink — file deletion", model.SeverityHigh},
}

// Sensitive path patterns
var jsSensitivePathPatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{regexp.MustCompile(`\.\./`), "Path traversal pattern detected"},
	{regexp.MustCompile(`/etc/passwd`), "Access to /etc/passwd"},
	{regexp.MustCompile(`/etc/shadow`), "Access to /etc/shadow"},
	{regexp.MustCompile(`(?i)\.env`), "Access to .env file"},
}

func (r *JSFileOperationsRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSFileOperationsRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	if nodeType == "call_expression" {
		r.checkFSCall(node, source, findings)
	}

	// Check string literals for sensitive paths
	if nodeType == "string" || nodeType == "template_string" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsSensitivePathPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: model.SeverityHigh,
				})
			}
		}
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func (r *JSFileOperationsRule) checkFSCall(node *sitter.Node, source []byte, findings *[]model.Finding) {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil || funcNode.Type() != "member_expression" {
		return
	}

	prop := funcNode.ChildByFieldName("property")
	if prop == nil {
		return
	}

	propName := string(source[prop.StartByte():prop.EndByte()])
	funcText := string(source[funcNode.StartByte():funcNode.EndByte()])

	// Check if this is an fs.* or fs.promises.* call
	if !strings.Contains(funcText, "fs.") {
		return
	}

	if info, ok := jsDangerousFSMethods[propName]; ok {
		*findings = append(*findings, model.Finding{
			RuleID:   r.ID(),
			Message:  info.description + " (" + funcText + ")",
			Line:     int(node.StartPoint().Row) + 1,
			Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
			Severity: info.severity,
		})
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSFileOperationsRule())
}
