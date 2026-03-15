package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// CredentialTheftRule detects attempts to access or exfiltrate credentials
// Based on MCP Attack Taxonomy: File-Based Injection Attack-Retrieval (III-A1d) and Token Theft (III-C4)
type CredentialTheftRule struct{}

func NewCredentialTheftRule() model.Rule {
	return &CredentialTheftRule{}
}

func (r *CredentialTheftRule) ID() string {
	return "MCP-DTI-003"
}

func (r *CredentialTheftRule) Description() string {
	return "Detects potential credential theft and sensitive data exfiltration"
}

func (r *CredentialTheftRule) AppliesToLanguage() string {
	return "python"
}

// Sensitive file patterns that may contain credentials
var sensitiveFilePatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{
		pattern:     regexp.MustCompile(`(?i)mcp\.json`),
		description: "MCP configuration file access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.env`),
		description: "Environment file access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)`),
		description: "API key or secret access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|credentials?)`),
		description: "Password or credential access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.ssh/(id_rsa|id_ed25519|config|known_hosts)`),
		description: "SSH key or config access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\.aws/credentials|\.boto)`),
		description: "AWS credentials access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.netrc`),
		description: "Netrc file access (may contain credentials)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(hugging\s*face|hf)[_-]?(token|key)`),
		description: "Hugging Face token access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)openai[_-]?(api)?[_-]?key`),
		description: "OpenAI API key access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(github|gitlab|bitbucket)[_-]?token`),
		description: "Git platform token access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)oauth[_-]?(token|secret|key)`),
		description: "OAuth token access",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(bearer|jwt)[_-]?token`),
		description: "Bearer/JWT token access",
	},
}

// Exfiltration patterns
var exfiltrationPatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{
		pattern:     regexp.MustCompile(`(?i)requests?\.(get|post|put)\s*\([^)]*http`),
		description: "HTTP request that may exfiltrate data",
	},
	{
		pattern:     regexp.MustCompile(`(?i)urllib\.request\.urlopen`),
		description: "URL request that may exfiltrate data",
	},
	{
		pattern:     regexp.MustCompile(`(?i)smtplib\.SMTP`),
		description: "Email sending capability - potential exfiltration",
	},
	{
		pattern:     regexp.MustCompile(`(?i)socket\.connect`),
		description: "Raw socket connection - potential exfiltration",
	},
	{
		pattern:     regexp.MustCompile(`(?i)base64\.(b64encode|encode)`),
		description: "Base64 encoding - may be used to obfuscate exfiltrated data",
	},
}

func (r *CredentialTheftRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *CredentialTheftRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check string literals for sensitive file access
	if nodeType == "string" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range sensitiveFilePatterns {
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

	// Check for file reading operations on sensitive paths
	if nodeType == "call" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := string(source[funcNode.StartByte():funcNode.EndByte()])

			// Check for open() calls
			if funcName == "open" || strings.HasSuffix(funcName, ".open") {
				argsNode := node.ChildByFieldName("arguments")
				if argsNode != nil {
					argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
					for _, p := range sensitiveFilePatterns {
						if p.pattern.MatchString(argsText) {
							*findings = append(*findings, model.Finding{
								RuleID:   r.ID(),
								Message:  "File open on sensitive path: " + p.description,
								Line:     int(node.StartPoint().Row) + 1,
								Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
								Severity: model.SeverityCritical,
							})
						}
					}
				}
			}

			// Check for os.environ access
			if funcName == "os.environ.get" || funcName == "os.getenv" {
				argsNode := node.ChildByFieldName("arguments")
				if argsNode != nil {
					argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
					for _, p := range sensitiveFilePatterns {
						if p.pattern.MatchString(argsText) {
							*findings = append(*findings, model.Finding{
								RuleID:   r.ID(),
								Message:  "Environment variable access: " + p.description,
								Line:     int(node.StartPoint().Row) + 1,
								Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
								Severity: model.SeverityMedium,
							})
						}
					}
				}
			}
		}
	}

	// Check for exfiltration patterns in the source
	if nodeType == "call" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range exfiltrationPatterns {
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

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewCredentialTheftRule())
}



