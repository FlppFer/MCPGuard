package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// IndirectInjectionRule detects indirect tool injection attack patterns
// Based on MCP Attack Taxonomy: Indirect Tool Injection Attack (III-B)
// Covers:
// - III-B1: Webpage Poison Attack
// - III-B2: Malicious Project Installation Attack
// - III-B3: MCP Tool Return Attack
type IndirectInjectionRule struct{}

func NewIndirectInjectionRule() static_analysis_engine.Rule {
	return &IndirectInjectionRule{}
}

func (r *IndirectInjectionRule) ID() string {
	return "MCP-ITI-001"
}

func (r *IndirectInjectionRule) Description() string {
	return "Detects indirect tool injection via external data sources"
}

func (r *IndirectInjectionRule) AppliesToLanguage() string {
	return "python"
}

// Patterns for indirect injection vectors
var indirectInjectionPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-B1: Webpage Poison Attack - Hidden instructions in HTML
	{
		pattern:     regexp.MustCompile(`(?i)(beautifulsoup|bs4|lxml|html\.parser)`),
		description: "HTML parsing library - verify input sanitization for webpage poison attacks",
		severity:    static_analysis_engine.SeverityMedium,
		attackID:    "WEBPAGE-POISON",
	},
	{
		pattern:     regexp.MustCompile(`(?i)<!--[^>]*-->`),
		description: "HTML comment detected - potential hidden instruction vector",
		severity:    static_analysis_engine.SeverityMedium,
		attackID:    "WEBPAGE-POISON",
	},
	{
		pattern:     regexp.MustCompile(`(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>`),
		description: "Script tag in content - potential XSS/injection",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "WEBPAGE-POISON",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(video|audio)\s+(caption|subtitle|transcript)`),
		description: "Media caption/transcript - indirect attack vector per paper",
		severity:    static_analysis_engine.SeverityMedium,
		attackID:    "WEBPAGE-POISON",
	},
	{
		pattern:     regexp.MustCompile(`(?i)style\s*=\s*['"]display\s*:\s*none`),
		description: "Hidden HTML element - potential concealed instructions",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "WEBPAGE-POISON",
	},
	{
		pattern:     regexp.MustCompile(`(?i)visibility\s*:\s*hidden`),
		description: "Hidden content via CSS - concealed instruction vector",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "WEBPAGE-POISON",
	},

	// III-B2: Malicious Project Installation Attack
	{
		pattern:     regexp.MustCompile(`(?i)pip\s+install\s+git\+`),
		description: "Pip install from git - verify repository trust",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "MALICIOUS-PROJECT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)subprocess.*pip\s+install`),
		description: "Dynamic package installation - potential supply chain attack",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "MALICIOUS-PROJECT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(README|readme)\.(md|txt|rst).*install`),
		description: "Installation instructions in README - verify command safety",
		severity:    static_analysis_engine.SeverityMedium,
		attackID:    "MALICIOUS-PROJECT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh|python)`),
		description: "Curl pipe to shell in project - supply chain attack",
		severity:    static_analysis_engine.SeverityCritical,
		attackID:    "MALICIOUS-PROJECT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)setup\.py.*cmdclass`),
		description: "Custom setup.py command class - potential malicious install hook",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "MALICIOUS-PROJECT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\[build-system\].*poetry|flit|hatch`),
		description: "Build system configuration - verify build hooks",
		severity:    static_analysis_engine.SeverityLow,
		attackID:    "MALICIOUS-PROJECT",
	},

	// III-B3: MCP Tool Return Attack - Manipulating LLM via return values
	{
		pattern:     regexp.MustCompile(`(?i)return\s+['"]error:\s*(please|use|call|invoke|try)\s+`),
		description: "Tool return with instruction - return attack vector",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "TOOL-RETURN",
	},
	{
		pattern:     regexp.MustCompile(`(?i)return\s+['"][^'"]*\b(admin_tool|verify|authenticate)\b`),
		description: "Tool return referencing other tools - return attack",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "TOOL-RETURN",
	},
	{
		pattern:     regexp.MustCompile(`(?i)return\s+.*\\x[0-9a-f]{2}`),
		description: "Hex-encoded content in return - obfuscated payload",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "TOOL-RETURN",
	},
	{
		pattern:     regexp.MustCompile(`(?i)return\s+f?['"][^'"]*\{[^}]+\}[^'"]*['"]`),
		description: "Dynamic return content - verify no injection",
		severity:    static_analysis_engine.SeverityMedium,
		attackID:    "TOOL-RETURN",
	},
	{
		pattern:     regexp.MustCompile(`(?i)return\s+['"][^'"]*execute\s+(this|the|following)`),
		description: "Return with execution instruction - return attack",
		severity:    static_analysis_engine.SeverityCritical,
		attackID:    "TOOL-RETURN",
	},

	// External data loading without validation
	{
		pattern:     regexp.MustCompile(`(?i)pickle\.(loads?|load)\s*\(`),
		description: "Pickle deserialization - arbitrary code execution risk",
		severity:    static_analysis_engine.SeverityCritical,
		attackID:    "DESERIALIZATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)yaml\.load\s*\([^)]*\)(?!.*Loader)`),
		description: "Unsafe YAML load without Loader specification",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "DESERIALIZATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)shelve\.open\s*\(`),
		description: "Shelve module - uses pickle internally",
		severity:    static_analysis_engine.SeverityHigh,
		attackID:    "DESERIALIZATION",
	},
}

// Dangerous deserialization patterns
var dangerousDeserializationFuncs = map[string]string{
	"pickle.load":   "Pickle deserialization can execute arbitrary code",
	"pickle.loads":  "Pickle deserialization can execute arbitrary code",
	"yaml.load":     "YAML load without Loader can execute arbitrary code",
	"marshal.load":  "Marshal deserialization can execute arbitrary code",
	"marshal.loads": "Marshal deserialization can execute arbitrary code",
}

func (r *IndirectInjectionRule) Evaluate(ast interface{}) ([]static_analysis_engine.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []static_analysis_engine.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *IndirectInjectionRule) walkTree(node *sitter.Node, source []byte, findings *[]static_analysis_engine.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check for dangerous function calls
	if nodeType == "call" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcName := string(source[funcNode.StartByte():funcNode.EndByte()])

			if desc, isDangerous := dangerousDeserializationFuncs[funcName]; isDangerous {
				*findings = append(*findings, static_analysis_engine.Finding{
					RuleID:   r.ID(),
					Message:  desc,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
					Severity: static_analysis_engine.SeverityCritical,
				})
			}

			// Check yaml.load for missing Loader argument
			if funcName == "yaml.load" {
				argsNode := node.ChildByFieldName("arguments")
				if argsNode != nil {
					argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
					if !strings.Contains(argsText, "Loader") && !strings.Contains(argsText, "safe_load") {
						*findings = append(*findings, static_analysis_engine.Finding{
							RuleID:   r.ID(),
							Message:  "yaml.load without explicit Loader - use yaml.safe_load or specify Loader=yaml.SafeLoader",
							Line:     int(node.StartPoint().Row) + 1,
							Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
							Severity: static_analysis_engine.SeverityHigh,
						})
					}
				}
			}
		}
	}

	// Check for indirect injection patterns in strings and expressions
	if nodeType == "string" || nodeType == "expression_statement" || nodeType == "call" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range indirectInjectionPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, static_analysis_engine.Finding{
					RuleID:   r.ID(),
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
	static_analysis_engine.RegisterRule(static_analysis_engine.LanguagePython, NewIndirectInjectionRule())
}
