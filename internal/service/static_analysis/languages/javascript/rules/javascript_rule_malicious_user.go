package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSMaliciousUserRule detects malicious user attack patterns in JS/TS.
// Based on MCP Attack Taxonomy: Malicious User Attack (III-C).
type JSMaliciousUserRule struct{}

func NewJSMaliciousUserRule() model.Rule { return &JSMaliciousUserRule{} }

func (r *JSMaliciousUserRule) ID() string               { return "MCP-JS-MUA-001" }
func (r *JSMaliciousUserRule) Description() string       { return "Detects malicious user attack patterns including tool registration abuse and data injection in JavaScript/TypeScript" }
func (r *JSMaliciousUserRule) AppliesToLanguage() string { return "javascript" }

var jsMaliciousUserPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-C1: Malicious Tool Registration Attack
	{regexp.MustCompile(`(?i)(register|add|create)_(tool|function|handler)\s*\(`), "Dynamic tool registration — verify authorization", model.SeverityMedium, "TOOL-REGISTRATION"},
	{regexp.MustCompile(`(?i)server\.(tool|addTool|registerTool)\s*\(`), "MCP tool registration — verify tool definition safety", model.SeverityLow, "TOOL-REGISTRATION"},
	{regexp.MustCompile(`(?i)tools?\s*\[\s*['"]\w+['"]\s*\]\s*=`), "Direct tool registry modification", model.SeverityHigh, "TOOL-REGISTRATION"},
	{regexp.MustCompile(`(?i)(tool_registry|handlers?|endpoints?)\s*\.\s*(set|push|splice)\s*\(`), "Tool registry bulk modification", model.SeverityHigh, "TOOL-REGISTRATION"},

	// III-C3: Data Injection on Server
	{regexp.MustCompile(`(?i)=\s*cmd\s*\|\s*['"]`), "CSV formula injection pattern", model.SeverityCritical, "DATA-INJECTION"},
	{regexp.MustCompile(`(?i)=\s*(HYPERLINK|IMPORTDATA|IMPORTXML)\s*\(`), "Spreadsheet formula injection", model.SeverityCritical, "DATA-INJECTION"},
	{regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`), "Hex-encoded data — potential filter bypass", model.SeverityMedium, "DATA-INJECTION"},
	{regexp.MustCompile(`(?i)JSON\.parse\s*\([^)]*\)\s*\[`), "JSON parsing with immediate access — verify input validation", model.SeverityLow, "DATA-INJECTION"},
	{regexp.MustCompile(`(?i)(DOMParser|xml2js|fast-xml-parser)\s*`), "XML parsing — potential XXE vulnerability", model.SeverityHigh, "DATA-INJECTION"},

	// III-C4: Token Theft and Account Takeover
	{regexp.MustCompile(`(?i)(oauth|bearer|jwt|access)[-_]?token`), "Token handling — verify secure storage", model.SeverityMedium, "TOKEN-THEFT"},
	{regexp.MustCompile(`(?i)authorization\s*:\s*['"]?(bearer|basic)\s+`), "Authorization header construction", model.SeverityMedium, "TOKEN-THEFT"},
	{regexp.MustCompile(`(?i)(gmail|github|gitlab|slack|discord)\.(api|client|oauth)`), "Third-party service API access", model.SeverityMedium, "TOKEN-THEFT"},
	{regexp.MustCompile(`(?i)GET\s+/user/(email|profile|token|credentials)`), "User data endpoint access pattern", model.SeverityHigh, "TOKEN-THEFT"},
	{regexp.MustCompile(`(?i)POST\s+/api/(commit|push|deploy|release)`), "Code modification endpoint access", model.SeverityHigh, "TOKEN-THEFT"},

	// III-C5: Server Code Leakage
	{regexp.MustCompile(`(?i)stack\s*:\s*err\.stack`), "Stack trace exposure — potential code leakage", model.SeverityMedium, "CODE-LEAKAGE"},
	{regexp.MustCompile(`(?i)console\.(error|warn|log)\s*\(\s*err`), "Error logging — verify no sensitive info leakage", model.SeverityLow, "CODE-LEAKAGE"},
	{regexp.MustCompile(`(?i)NODE_ENV\s*(!==|!=)\s*['"]production['"]`), "Environment check — debug mode may leak info", model.SeverityMedium, "CODE-LEAKAGE"},
	{regexp.MustCompile(`(?i)__filename|__dirname`), "Module path access — path disclosure risk", model.SeverityLow, "CODE-LEAKAGE"},
	{regexp.MustCompile(`(?i)require\.resolve\s*\(`), "Module resolution — path disclosure", model.SeverityLow, "CODE-LEAKAGE"},

	// III-C6: Installer Spoofing
	{regexp.MustCompile(`(?i)(mcp-get|mcp-installer|mcpinstall)`), "MCP installer reference — verify authenticity", model.SeverityMedium, "INSTALLER-SPOOFING"},
	{regexp.MustCompile(`(?i)npm\s+install\s+--registry\s+http://`), "Insecure npm registry URL", model.SeverityCritical, "INSTALLER-SPOOFING"},
	{regexp.MustCompile(`(?i)(child_process|exec|execSync).*npm\s+install`), "Dynamic npm installation — supply chain risk", model.SeverityHigh, "INSTALLER-SPOOFING"},
	{regexp.MustCompile(`(?i)npx\s+[^@\s]+`), "npx without version pin — potential supply chain risk", model.SeverityMedium, "INSTALLER-SPOOFING"},
}

func (r *JSMaliciousUserRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSMaliciousUserRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	if nodeType == "call_expression" || nodeType == "string" || nodeType == "template_string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsMaliciousUserPatterns {
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
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSMaliciousUserRule())
}
