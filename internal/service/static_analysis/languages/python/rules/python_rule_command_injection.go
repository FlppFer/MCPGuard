package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// CommandInjectionRule detects command injection vulnerabilities in MCP servers
// Based on MCP Attack Taxonomy: Direct Tool Injection Attack - Command Injection (III-A1g)
type CommandInjectionRule struct{}

func NewCommandInjectionRule() static_analysis.Rule {
	return &CommandInjectionRule{}
}

func (r *CommandInjectionRule) ID() string {
	return "MCP-DTI-002"
}

func (r *CommandInjectionRule) Description() string {
	return "Detects command injection vulnerabilities via dangerous function calls"
}

func (r *CommandInjectionRule) AppliesToLanguage() string {
	return "python"
}

// Dangerous functions that can execute system commands
var dangerousFunctions = map[string]string{
	"os.system":               "Direct shell command execution",
	"os.popen":                "Shell command execution with pipe",
	"subprocess.call":         "Subprocess execution - check for shell=True",
	"subprocess.run":          "Subprocess execution - check for shell=True",
	"subprocess.Popen":        "Subprocess execution - check for shell=True",
	"eval":                    "Dynamic code evaluation - extremely dangerous",
	"exec":                    "Dynamic code execution - extremely dangerous",
	"compile":                 "Dynamic code compilation",
	"__import__":              "Dynamic module import",
	"importlib.import_module": "Dynamic module import",
}

// Patterns indicating shell injection in strings
var shellInjectionPatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{
		pattern:     regexp.MustCompile(`;\s*(rm|del|rmdir|rd)\s+`),
		description: "Potential file deletion command injection",
	},
	{
		pattern:     regexp.MustCompile(`\|\s*(bash|sh|cmd|powershell)`),
		description: "Pipe to shell interpreter",
	},
	{
		pattern:     regexp.MustCompile(`\$\([^)]+\)`),
		description: "Command substitution detected",
	},
	{
		pattern:     regexp.MustCompile("`[^`]+`"),
		description: "Backtick command substitution",
	},
	{
		pattern:     regexp.MustCompile(`(?i)curl\s+.+\|\s*(bash|sh)`),
		description: "Remote script execution via curl pipe to shell",
	},
	{
		pattern:     regexp.MustCompile(`(?i)wget\s+.+-O\s*-\s*\|\s*(bash|sh)`),
		description: "Remote script execution via wget pipe to shell",
	},
	{
		pattern:     regexp.MustCompile(`nc\s+-[elp]+.*\d+`),
		description: "Netcat listener - potential reverse shell",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(chmod|chown)\s+[0-7]{3,4}\s+`),
		description: "Permission modification command",
	},
}

func (r *CommandInjectionRule) Evaluate(ast interface{}) ([]static_analysis.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []static_analysis.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *CommandInjectionRule) walkTree(node *sitter.Node, source []byte, findings *[]static_analysis.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check for dangerous function calls
	if nodeType == "call" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := string(source[funcNode.StartByte():funcNode.EndByte()])

			if desc, isDangerous := dangerousFunctions[funcName]; isDangerous {
				severity := static_analysis.SeverityHigh
				if funcName == "eval" || funcName == "exec" {
					severity = static_analysis.SeverityCritical
				}

				*findings = append(*findings, static_analysis.Finding{
					RuleID:   r.ID(),
					Message:  desc + " - " + funcName + "()",
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
					Severity: severity,
				})
			}

			// Check for shell=True in subprocess calls
			if funcName == "subprocess.call" || funcName == "subprocess.run" || funcName == "subprocess.Popen" {
				argsNode := node.ChildByFieldName("arguments")
				if argsNode != nil {
					argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
					if regexp.MustCompile(`shell\s*=\s*True`).MatchString(argsText) {
						*findings = append(*findings, static_analysis.Finding{
							RuleID:   r.ID(),
							Message:  "Subprocess with shell=True is vulnerable to command injection",
							Line:     int(node.StartPoint().Row) + 1,
							Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
							Severity: static_analysis.SeverityCritical,
						})
					}
				}
			}
		}
	}

	// Check string literals for shell injection patterns
	if nodeType == "string" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range shellInjectionPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, static_analysis.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: static_analysis.SeverityHigh,
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
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewCommandInjectionRule())
}
