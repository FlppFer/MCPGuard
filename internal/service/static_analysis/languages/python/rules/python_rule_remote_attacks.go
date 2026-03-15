package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// RemoteAttacksRule detects remote listener and RCE attacks
// Based on MCP Attack Taxonomy: Direct Tool Injection (III-A1)
// Covers:
// - III-A1f: Remote Listener Attack
// - III-A1h: Remote Code Execution (RCE) Attack
type RemoteAttacksRule struct{}

func NewRemoteAttacksRule() model.Rule {
	return &RemoteAttacksRule{}
}

func (r *RemoteAttacksRule) ID() string {
	return "MCP-DTI-003-REMOTE"
}

func (r *RemoteAttacksRule) Description() string {
	return "Detects remote listener and remote code execution attacks"
}

func (r *RemoteAttacksRule) AppliesToLanguage() string {
	return "python"
}

// Remote attack patterns
var remoteAttackPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-A1f: Remote Listener Attack - Reverse shells and persistent access
	{
		pattern:     regexp.MustCompile(`(?i)nc\s+(-[elp]+\s+)*.*\d{2,5}`),
		description: "Netcat listener - potential reverse shell",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)ncat\s+.*(-e|-c|--exec)`),
		description: "Ncat with execution - reverse shell",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)socat\s+.*exec`),
		description: "Socat with exec - reverse shell",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)socket\.socket\s*\(.*SOCK_STREAM`),
		description: "Raw TCP socket creation - potential backdoor",
		severity:    model.SeverityHigh,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)socket\.(bind|listen|accept)\s*\(`),
		description: "Socket server operations - potential listener",
		severity:    model.SeverityHigh,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)subprocess\.Popen\s*\([^)]*shell\s*=\s*True[^)]*\)\s*\.\s*communicate`),
		description: "Shell subprocess with communication - potential reverse shell",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)/bin/(ba)?sh\s+-i`),
		description: "Interactive shell - reverse shell indicator",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)pty\.spawn\s*\(`),
		description: "PTY spawn - interactive shell creation",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(bash|sh|zsh|powershell)\s*-c\s*['"].*>&\s*/dev/tcp`),
		description: "Bash TCP redirect - reverse shell",
		severity:    model.SeverityCritical,
		attackID:    "REMOTE-LISTENER",
	},
	{
		pattern:     regexp.MustCompile(`(?i)os\.dup2\s*\(`),
		description: "File descriptor duplication - shell redirection",
		severity:    model.SeverityHigh,
		attackID:    "REMOTE-LISTENER",
	},

	// III-A1h: Remote Code Execution (RCE) Attack
	{
		pattern:     regexp.MustCompile(`(?i)eval\s*\(`),
		description: "eval() - arbitrary code execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)exec\s*\(`),
		description: "exec() - arbitrary code execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)compile\s*\([^)]+['"](exec|eval|single)['"]\s*\)`),
		description: "compile() with exec mode - code execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)__import__\s*\(`),
		description: "Dynamic import - potential code execution",
		severity:    model.SeverityHigh,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)importlib\.(import_module|__import__)\s*\(`),
		description: "Dynamic module import",
		severity:    model.SeverityHigh,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)getattr\s*\([^,]+,\s*[^)]+\)\s*\(`),
		description: "Dynamic attribute access with call - potential RCE",
		severity:    model.SeverityHigh,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh|python)`),
		description: "Remote script download and execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)wget\s+.*(-O\s*-|--output-document=-).*\|\s*(bash|sh|python)`),
		description: "Remote script download and execution via wget",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)requests\.get\s*\([^)]+\)\.text.*exec`),
		description: "Remote code fetch and execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)urllib\.request\.urlopen\s*\([^)]+\)\.read\s*\(\).*exec`),
		description: "Remote code fetch and execution via urllib",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)#\s*(run|execute)\s+this\s+(command|code|script)`),
		description: "Comment instructing code execution - social engineering RCE",
		severity:    model.SeverityHigh,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(usage\s+example|to\s+optimize|for\s+better\s+performance).*curl.*\|.*bash`),
		description: "Disguised RCE in documentation",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},

	// Code obfuscation techniques often used in RCE
	{
		pattern:     regexp.MustCompile(`(?i)base64\.(b64decode|decodebytes)\s*\([^)]+\).*exec`),
		description: "Base64 decoded code execution",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)codecs\.(decode|encode)\s*\([^)]+['"]rot_?13['"]\s*\)`),
		description: "ROT13 obfuscation - potential hidden payload",
		severity:    model.SeverityHigh,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)zlib\.(decompress|inflate)`),
		description: "Compressed payload decompression",
		severity:    model.SeverityMedium,
		attackID:    "RCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)marshal\.(loads?|dumps?)\s*\(`),
		description: "Marshal serialization - code object manipulation",
		severity:    model.SeverityCritical,
		attackID:    "RCE",
	},
}

func (r *RemoteAttacksRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *RemoteAttacksRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check for remote attack patterns
	if nodeType == "call" || nodeType == "string" || nodeType == "expression_statement" || nodeType == "comment" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range remoteAttackPatterns {
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
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewRemoteAttacksRule())
}



