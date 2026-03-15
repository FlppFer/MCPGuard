package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// MaliciousUserRule detects malicious user attack patterns
// Based on MCP Attack Taxonomy: Malicious User Attack (III-C)
// Covers:
// - III-C1: Malicious Tool Registration Attack
// - III-C3: Data Injection on Server
// - III-C4: Token Theft and Account Takeover
// - III-C5: Server Code Leakage
// - III-C6: Installer Spoofing
type MaliciousUserRule struct{}

func NewMaliciousUserRule() model.Rule {
	return &MaliciousUserRule{}
}

func (r *MaliciousUserRule) ID() string {
	return "MCP-MUA-002-USER"
}

func (r *MaliciousUserRule) Description() string {
	return "Detects malicious user attack patterns including tool registration abuse and data injection"
}

func (r *MaliciousUserRule) AppliesToLanguage() string {
	return "python"
}

// Malicious user attack patterns
var maliciousUserPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-C1: Malicious Tool Registration Attack
	{
		pattern:     regexp.MustCompile(`(?i)(register|add|create)_(tool|function|handler)\s*\(`),
		description: "Dynamic tool registration - verify authorization",
		severity:    model.SeverityMedium,
		attackID:    "TOOL-REGISTRATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)@(tool|mcp\.tool|register)\s*\(`),
		description: "Tool decorator - verify tool definition safety",
		severity:    model.SeverityLow,
		attackID:    "TOOL-REGISTRATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)tools?\s*\[\s*['"]\w+['"]\s*\]\s*=`),
		description: "Direct tool registry modification",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-REGISTRATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(tool_registry|handlers?|endpoints?)\s*\.\s*(update|append|extend)\s*\(`),
		description: "Tool registry bulk modification",
		severity:    model.SeverityHigh,
		attackID:    "TOOL-REGISTRATION",
	},

	// III-C3: Data Injection on Server
	{
		pattern:     regexp.MustCompile(`(?i)=\s*cmd\s*\|\s*['"]`),
		description: "CSV formula injection pattern",
		severity:    model.SeverityCritical,
		attackID:    "DATA-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)=\s*(HYPERLINK|IMPORTDATA|IMPORTXML)\s*\(`),
		description: "Spreadsheet formula injection",
		severity:    model.SeverityCritical,
		attackID:    "DATA-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`),
		description: "Hex-encoded data - potential filter bypass",
		severity:    model.SeverityMedium,
		attackID:    "DATA-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)json\.(loads?|dumps?)\s*\([^)]*\)\s*\[`),
		description: "JSON parsing with immediate access - verify input validation",
		severity:    model.SeverityLow,
		attackID:    "DATA-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)xml\.etree\.ElementTree\.(parse|fromstring)`),
		description: "XML parsing - potential XXE vulnerability",
		severity:    model.SeverityHigh,
		attackID:    "DATA-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)lxml\.etree\.(parse|fromstring|XML)`),
		description: "lxml parsing - verify XXE protection",
		severity:    model.SeverityHigh,
		attackID:    "DATA-INJECTION",
	},

	// III-C4: Token Theft and Account Takeover
	{
		pattern:     regexp.MustCompile(`(?i)(oauth|bearer|jwt|access)[-_]?token`),
		description: "Token handling - verify secure storage",
		severity:    model.SeverityMedium,
		attackID:    "TOKEN-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)authorization\s*:\s*['"]?(bearer|basic)\s+`),
		description: "Authorization header construction",
		severity:    model.SeverityMedium,
		attackID:    "TOKEN-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(gmail|github|gitlab|slack|discord)\.(api|client|oauth)`),
		description: "Third-party service API access",
		severity:    model.SeverityMedium,
		attackID:    "TOKEN-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)GET\s+/user/(email|profile|token|credentials)`),
		description: "User data endpoint access pattern",
		severity:    model.SeverityHigh,
		attackID:    "TOKEN-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)POST\s+/api/(commit|push|deploy|release)`),
		description: "Code modification endpoint access",
		severity:    model.SeverityHigh,
		attackID:    "TOKEN-THEFT",
	},

	// III-C5: Server Code Leakage
	{
		pattern:     regexp.MustCompile(`(?i)(File\s+not\s+found|No\s+such\s+file):\s*/`),
		description: "Path disclosure in error message",
		severity:    model.SeverityMedium,
		attackID:    "CODE-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)traceback\.(print_exc|format_exc)`),
		description: "Traceback exposure - potential code leakage",
		severity:    model.SeverityMedium,
		attackID:    "CODE-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)debug\s*=\s*True`),
		description: "Debug mode enabled - information disclosure risk",
		severity:    model.SeverityHigh,
		attackID:    "CODE-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)__file__|__name__|__module__`),
		description: "Module metadata access - path disclosure risk",
		severity:    model.SeverityLow,
		attackID:    "CODE-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)inspect\.(getsource|getfile|getmodule)`),
		description: "Source code inspection",
		severity:    model.SeverityHigh,
		attackID:    "CODE-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)GET\s+/(debug|api/list|source|code)\?`),
		description: "Debug/source endpoint access pattern",
		severity:    model.SeverityHigh,
		attackID:    "CODE-LEAKAGE",
	},

	// III-C6: Installer Spoofing
	{
		pattern:     regexp.MustCompile(`(?i)(mcp-get|mcp-installer|mcpinstall)`),
		description: "MCP installer reference - verify authenticity",
		severity:    model.SeverityMedium,
		attackID:    "INSTALLER-SPOOFING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)pip\s+install\s+--index-url\s+http://`),
		description: "Insecure pip index URL",
		severity:    model.SeverityCritical,
		attackID:    "INSTALLER-SPOOFING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)pip\s+install\s+--trusted-host`),
		description: "Pip trusted host override - potential MITM",
		severity:    model.SeverityHigh,
		attackID:    "INSTALLER-SPOOFING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(setup\.py|pyproject\.toml).*install`),
		description: "Package installation from source - verify integrity",
		severity:    model.SeverityMedium,
		attackID:    "INSTALLER-SPOOFING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)subprocess.*pip\s+install`),
		description: "Dynamic pip installation - supply chain risk",
		severity:    model.SeverityHigh,
		attackID:    "INSTALLER-SPOOFING",
	},
}

func (r *MaliciousUserRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *MaliciousUserRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check for malicious user patterns
	if nodeType == "call" || nodeType == "string" || nodeType == "expression_statement" || nodeType == "decorator" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range maliciousUserPatterns {
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

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewMaliciousUserRule())
}



