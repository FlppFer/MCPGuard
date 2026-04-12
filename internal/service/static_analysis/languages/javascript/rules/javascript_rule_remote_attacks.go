package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSRemoteAttacksRule detects remote listener and RCE attacks in JS/TS.
// Based on MCP Attack Taxonomy: Direct Tool Injection (III-A1f, III-A1h).
type JSRemoteAttacksRule struct{}

func NewJSRemoteAttacksRule() model.Rule { return &JSRemoteAttacksRule{} }

func (r *JSRemoteAttacksRule) ID() string               { return "MCP-JS-REM-001" }
func (r *JSRemoteAttacksRule) Description() string       { return "Detects remote listener and remote code execution attacks in JavaScript/TypeScript" }
func (r *JSRemoteAttacksRule) AppliesToLanguage() string { return "javascript" }

var jsRemoteAttackPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-A1f: Remote Listener Attack
	{regexp.MustCompile(`(?i)nc\s+(-[elp]+\s+)*.*\d{2,5}`), "Netcat listener — potential reverse shell", model.SeverityCritical, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)ncat\s+.*(-e|-c|--exec)`), "Ncat with execution — reverse shell", model.SeverityCritical, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)socat\s+.*exec`), "Socat with exec — reverse shell", model.SeverityCritical, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)net\.createServer\s*\(`), "TCP server creation — potential backdoor listener", model.SeverityHigh, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)net\.createConnection\s*\(`), "TCP connection — potential reverse shell", model.SeverityHigh, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)dgram\.createSocket\s*\(`), "UDP socket creation — potential covert channel", model.SeverityMedium, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)/bin/(ba)?sh\s+-i`), "Interactive shell — reverse shell indicator", model.SeverityCritical, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)(bash|sh|zsh|powershell)\s*-c\s*['"].*>&\s*/dev/tcp`), "Bash TCP redirect — reverse shell", model.SeverityCritical, "REMOTE-LISTENER"},
	{regexp.MustCompile(`(?i)WebSocket\s*\(\s*['"]ws`), "WebSocket connection — potential C2 channel", model.SeverityMedium, "REMOTE-LISTENER"},

	// III-A1h: Remote Code Execution (RCE) Attack
	{regexp.MustCompile(`(?i)eval\s*\(`), "eval() — arbitrary code execution", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)new\s+Function\s*\(`), "Function constructor — dynamic code execution", model.SeverityHigh, "RCE"},
	{regexp.MustCompile(`(?i)vm\.(runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(`), "V8 VM execution — code execution", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]\s*\)`), "child_process import — command execution capability", model.SeverityHigh, "RCE"},
	{regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh|node)`), "Remote script download and execution", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)wget\s+.*(-O\s*-|--output-document=-).*\|\s*(bash|sh|node)`), "Remote script download and execution via wget", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)fetch\s*\([^)]+\)\.then[^)]*\.\s*text\s*\(\s*\).*eval`), "Remote code fetch and eval", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)#\s*(run|execute)\s+this\s+(command|code|script)`), "Comment instructing code execution — social engineering RCE", model.SeverityHigh, "RCE"},

	// Code obfuscation techniques
	{regexp.MustCompile(`(?i)atob\s*\([^)]+\).*eval`), "Base64 decoded code execution", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)\.toString\s*\(\).*eval`), "Base64 buffer decode and eval", model.SeverityCritical, "RCE"},
	{regexp.MustCompile(`(?i)String\.fromCharCode\s*\(`), "Character code construction — potential obfuscation", model.SeverityMedium, "RCE"},
	{regexp.MustCompile(`(?i)\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}`), "Unicode escape sequences — potential obfuscated payload", model.SeverityMedium, "RCE"},
}

func (r *JSRemoteAttacksRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSRemoteAttacksRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	if nodeType == "call_expression" || nodeType == "string" || nodeType == "template_string" || nodeType == "expression_statement" || nodeType == "comment" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsRemoteAttackPatterns {
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

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSRemoteAttacksRule())
}
