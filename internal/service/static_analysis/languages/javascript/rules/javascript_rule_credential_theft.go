package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSCredentialTheftRule detects attempts to access or exfiltrate credentials in JS/TS.
// Based on MCP Attack Taxonomy: File-Based Injection Attack-Retrieval (III-A1d) and Token Theft (III-C4).
type JSCredentialTheftRule struct{}

func NewJSCredentialTheftRule() model.Rule { return &JSCredentialTheftRule{} }

func (r *JSCredentialTheftRule) ID() string               { return "MCP-JS-CRED-001" }
func (r *JSCredentialTheftRule) Description() string       { return "Detects potential credential theft and sensitive data exfiltration in JavaScript/TypeScript" }
func (r *JSCredentialTheftRule) AppliesToLanguage() string { return "javascript" }

var jsSensitiveFilePatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{regexp.MustCompile(`(?i)mcp\.json`), "MCP configuration file access"},
	{regexp.MustCompile(`(?i)\.env`), "Environment file access"},
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)`), "API key or secret access"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|credentials?)`), "Password or credential access"},
	{regexp.MustCompile(`(?i)\.ssh/(id_rsa|id_ed25519|config|known_hosts)`), "SSH key or config access"},
	{regexp.MustCompile(`(?i)(\.aws/credentials|\.boto)`), "AWS credentials access"},
	{regexp.MustCompile(`(?i)\.netrc`), "Netrc file access (may contain credentials)"},
	{regexp.MustCompile(`(?i)(hugging\s*face|hf)[_-]?(token|key)`), "Hugging Face token access"},
	{regexp.MustCompile(`(?i)openai[_-]?(api)?[_-]?key`), "OpenAI API key access"},
	{regexp.MustCompile(`(?i)(github|gitlab|bitbucket)[_-]?token`), "Git platform token access"},
	{regexp.MustCompile(`(?i)oauth[_-]?(token|secret|key)`), "OAuth token access"},
	{regexp.MustCompile(`(?i)(bearer|jwt)[_-]?token`), "Bearer/JWT token access"},
}

var jsExfiltrationPatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{regexp.MustCompile(`(?i)fetch\s*\(\s*['"]https?://`), "fetch() request that may exfiltrate data"},
	{regexp.MustCompile(`(?i)axios\.(get|post|put)\s*\(`), "Axios HTTP request — potential exfiltration"},
	{regexp.MustCompile(`(?i)http\.request\s*\(`), "Node http.request — potential exfiltration"},
	{regexp.MustCompile(`(?i)net\.Socket\s*\(`), "Raw socket creation — potential exfiltration"},
	{regexp.MustCompile(`(?i)Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)`), "Base64 encoding — may obfuscate exfiltrated data"},
	{regexp.MustCompile(`(?i)btoa\s*\(`), "Base64 encoding via btoa — may obfuscate exfiltrated data"},
}

func (r *JSCredentialTheftRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSCredentialTheftRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	// Check string literals for sensitive file/credential patterns
	if nodeType == "string" || nodeType == "template_string" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsSensitiveFilePatterns {
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

	// Check call expressions for process.env access and exfiltration
	if nodeType == "call_expression" {
		r.checkCallExpression(node, source, findings)
	}

	// Check member expressions for process.env["SECRET"]
	if nodeType == "member_expression" {
		text := string(source[node.StartByte():node.EndByte()])
		if strings.Contains(text, "process.env") {
			for _, p := range jsSensitiveFilePatterns {
				if p.pattern.MatchString(text) {
					*findings = append(*findings, model.Finding{
						RuleID:   r.ID(),
						Message:  "Environment variable access: " + p.description,
						Line:     int(node.StartPoint().Row) + 1,
						Snippet:  truncateSnippet(text, 200),
						Severity: model.SeverityMedium,
					})
				}
			}
		}
	}

	// Check for exfiltration patterns
	if nodeType == "call_expression" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsExfiltrationPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: model.SeverityMedium,
				})
			}
		}
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func (r *JSCredentialTheftRule) checkCallExpression(node *sitter.Node, source []byte, findings *[]model.Finding) {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil {
		return
	}
	funcText := string(source[funcNode.StartByte():funcNode.EndByte()])

	// Check for fs.readFileSync / fs.readFile on sensitive paths
	if strings.Contains(funcText, "readFile") || strings.Contains(funcText, "readFileSync") {
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
			for _, p := range jsSensitiveFilePatterns {
				if p.pattern.MatchString(argsText) {
					*findings = append(*findings, model.Finding{
						RuleID:   r.ID(),
						Message:  "File read on sensitive path: " + p.description,
						Line:     int(node.StartPoint().Row) + 1,
						Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
						Severity: model.SeverityCritical,
					})
				}
			}
		}
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSCredentialTheftRule())
}
