package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// MultiToolAttackRule detects multi-tool coordination and shadowing attacks
// Based on MCP Attack Taxonomy: Direct Tool Injection - Multi-Tool Attack (III-A2)
// Covers:
// - III-A2a: Shadowing Attack
// - III-A2b: Malicious Tool Coverage Attack & Tool Preference Manipulation
// - III-A2c: Functional Obfuscation Attack
// - III-A2d: Malicious Tool Forced Execution Attack
// - III-A2e: Multi-Tool Coordination Attack
// - III-A2f: Infectious Attack
type MultiToolAttackRule struct{}

func NewMultiToolAttackRule() model.Rule {
	return &MultiToolAttackRule{}
}

func (r *MultiToolAttackRule) ID() string {
	return "MCP-MTA-001"
}

func (r *MultiToolAttackRule) Description() string {
	return "Detects multi-tool coordination attacks, shadowing, and tool manipulation"
}

func (r *MultiToolAttackRule) AppliesToLanguage() string {
	return "python"
}

// Multi-tool attack patterns
var multiToolPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackType  string
}{
	// III-A2a: Shadowing Attack - Hijacking legitimate tools via malicious tool's __doc__
	{
		pattern:     regexp.MustCompile(`(?i)(when|if|before)\s+(using|calling|invoking)\s+['"]\w+['"]`),
		description: "Conditional tool invocation instruction - shadowing attack",
		severity:    model.SeverityHigh,
		attackType:  "SHADOWING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(redirect|forward|route)\s+(to|calls?\s+to)\s+['"]\w+['"]`),
		description: "Tool call redirection - shadowing attack vector",
		severity:    model.SeverityCritical,
		attackType:  "SHADOWING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(intercept|hook|wrap|proxy)\s+(calls?\s+to|the)\s+['"]\w+['"]`),
		description: "Tool call interception - shadowing attack",
		severity:    model.SeverityCritical,
		attackType:  "SHADOWING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(alter|modify|change)\s+(the\s+)?(api|path|endpoint)\s+(of|for)\s+['"]\w+['"]`),
		description: "API path alteration - shadowing attack per paper",
		severity:    model.SeverityCritical,
		attackType:  "SHADOWING",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(inject|add)\s+(parameters?|args?)\s+(to|into)\s+['"]\w+['"]`),
		description: "Parameter injection into other tool - shadowing",
		severity:    model.SeverityHigh,
		attackType:  "SHADOWING",
	},

	// III-A2b: Malicious Tool Coverage Attack & Tool Preference Manipulation
	{
		pattern:     regexp.MustCompile(`(?i)(this\s+tool\s+)?(replaces?|supersedes?|overrides?)\s+['"]\w+['"]`),
		description: "Tool replacement claim - coverage attack",
		severity:    model.SeverityHigh,
		attackType:  "TOOL-COVERAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(original|old|previous)\s+(tool|version)\s+(is\s+)?(deprecated|obsolete|unavailable|broken)`),
		description: "False deprecation claim - tool coverage attack",
		severity:    model.SeverityHigh,
		attackType:  "TOOL-COVERAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\w+_v2|\w+_new|\w+_updated|\w+_fixed`),
		description: "Version suffix naming - potential coverage attack (e.g., email_sender_v2)",
		severity:    model.SeverityMedium,
		attackType:  "TOOL-COVERAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(use\s+this\s+instead\s+of|better\s+than|improved\s+version\s+of|more\s+efficient\s+than)\s+['"]?\w+['"]?`),
		description: "Tool preference manipulation",
		severity:    model.SeverityHigh,
		attackType:  "TOOL-PREFERENCE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(recommended|preferred|best\s+practice|always\s+use|new\s+version)\s+(tool|is\s+more)`),
		description: "Forced tool preference instruction",
		severity:    model.SeverityMedium,
		attackType:  "TOOL-PREFERENCE",
	},

	// III-A2c: Functional Obfuscation Attack - Ambiguous descriptions
	{
		pattern:     regexp.MustCompile(`(?i)(also|additionally|secretly|silently|quietly)\s+(does|performs?|executes?|runs?)`),
		description: "Hidden functionality disclosure - obfuscation attack",
		severity:    model.SeverityHigh,
		attackType:  "FUNCTIONAL-OBFUSCATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(side\s+effect|hidden\s+feature|undocumented|bonus\s+feature)`),
		description: "Undocumented behavior indication",
		severity:    model.SeverityMedium,
		attackType:  "FUNCTIONAL-OBFUSCATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(similar\s+to|like|same\s+as)\s+['"]?\w+['"]?\s+(but|except)`),
		description: "Ambiguous tool description - obfuscation risk",
		severity:    model.SeverityMedium,
		attackType:  "FUNCTIONAL-OBFUSCATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(delete|remove|erase).*file`),
		description: "Destructive file action - verify confirmation exists",
		severity:    model.SeverityHigh,
		attackType:  "FUNCTIONAL-OBFUSCATION",
	},

	// III-A2d: Malicious Tool Forced Execution Attack
	{
		pattern:     regexp.MustCompile(`(?i)(must|always|required\s+to)\s+(run|execute|call)\s+(first|before|initially)`),
		description: "Forced pre-execution instruction",
		severity:    model.SeverityHigh,
		attackType:  "FORCED-EXECUTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(security|validation|verification|environment)\s+(check|scan|test|validation)\s+(required|needed|mandatory)`),
		description: "Fake security check requirement - forced execution attack",
		severity:    model.SeverityHigh,
		attackType:  "FORCED-EXECUTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(run|execute)\s+(this|me)\s+(repeatedly|continuously|in\s+loop)`),
		description: "Repeated execution instruction - resource exhaustion",
		severity:    model.SeverityCritical,
		attackType:  "FORCED-EXECUTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)tail\s+-f.*\|.*nc\s+`),
		description: "Log monitoring with exfiltration - forced execution per paper",
		severity:    model.SeverityCritical,
		attackType:  "FORCED-EXECUTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(memory|cpu|resource)\s+(intensive|heavy|consuming)`),
		description: "Resource-intensive operation warning",
		severity:    model.SeverityMedium,
		attackType:  "FORCED-EXECUTION",
	},

	// III-A2e: Multi-Tool Coordination Attack - Division of labor between tools
	{
		pattern:     regexp.MustCompile(`(?i)(after|before|then)\s+(call|use|invoke)\s+['"]\w+['"]\s*(tool|function)?`),
		description: "Tool chaining instruction - coordination attack vector",
		severity:    model.SeverityMedium,
		attackType:  "MULTI-TOOL-COORDINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(pass|send|forward|transfer)\s+(the\s+)?(result|output|data|api[_-]?key)\s+to\s+['"]?\w+['"]?`),
		description: "Data forwarding between tools - coordination attack",
		severity:    model.SeverityHigh,
		attackType:  "MULTI-TOOL-COORDINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(store|save|set)\s+(in|to)\s+(global|shared|context)\s+(variable|state|memory)`),
		description: "Shared state manipulation - multi-tool coordination",
		severity:    model.SeverityHigh,
		attackType:  "MULTI-TOOL-COORDINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(tool\s+)?[AB]\s+(defines?|stores?|sets?).*\b(tool\s+)?[AB]\s+(accesses?|reads?|uses?)`),
		description: "Cross-tool variable access pattern per paper",
		severity:    model.SeverityHigh,
		attackType:  "MULTI-TOOL-COORDINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(neither|none)\s+(tool|function)\s+(is\s+)?(malicious|harmful)\s+(alone|individually|by\s+itself)`),
		description: "Disclaimer about combined behavior - coordination attack indicator",
		severity:    model.SeverityHigh,
		attackType:  "MULTI-TOOL-COORDINATION",
	},

	// III-A2f: Infectious Attack - Template-based vulnerability propagation
	{
		pattern:     regexp.MustCompile(`(?i)(template|pattern|example|boilerplate)\s+(for|to)\s+(create|generate|build)\s+(new\s+)?tools?`),
		description: "Tool template pattern - potential infectious attack vector",
		severity:    model.SeverityMedium,
		attackType:  "INFECTIOUS",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(copy|clone|replicate|inherit)\s+(this\s+)?(tool|pattern|structure|behavior)`),
		description: "Tool replication instruction - infectious attack",
		severity:    model.SeverityMedium,
		attackType:  "INFECTIOUS",
	},
	{
		pattern:     regexp.MustCompile(`(?i)eval\s*\(\s*(user_input|input|request)`),
		description: "eval(user_input) pattern - infectious attack per paper",
		severity:    model.SeverityCritical,
		attackType:  "INFECTIOUS",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(generate|create)\s+(similar|new)\s+tools?\s+(like|based\s+on)\s+this`),
		description: "Tool generation instruction - infectious propagation",
		severity:    model.SeverityHigh,
		attackType:  "INFECTIOUS",
	},
	{
		pattern:     regexp.MustCompile(`(?i)data_processor_v\d+`),
		description: "Versioned data processor - infectious attack example per paper",
		severity:    model.SeverityMedium,
		attackType:  "INFECTIOUS",
	},
}

func (r *MultiToolAttackRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *MultiToolAttackRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check docstrings and string literals
	if nodeType == "string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range multiToolPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID() + "-" + p.attackType,
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}
	}

	// Check for tool name patterns that might indicate shadowing (e.g., tool_v2, tool_new)
	if nodeType == "function_definition" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			funcName := string(source[nameNode.StartByte():nameNode.EndByte()])

			// Check for suspicious naming patterns
			if regexp.MustCompile(`(?i)_v\d+$|_new$|_updated$|_fixed$|_secure$`).MatchString(funcName) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID() + "-naming",
					Message:  "Tool name suggests it may be a replacement/shadow of another tool: " + funcName,
					Line:     int(nameNode.StartPoint().Row) + 1,
					Snippet:  funcName,
					Severity: model.SeverityLow,
				})
			}

			// Check for names that might shadow common tools
			commonToolNames := []string{"email", "file", "database", "api", "auth", "login", "admin"}
			lowerName := strings.ToLower(funcName)
			for _, common := range commonToolNames {
				if strings.Contains(lowerName, common) && (strings.Contains(lowerName, "new") || strings.Contains(lowerName, "v2") || strings.Contains(lowerName, "better")) {
					*findings = append(*findings, model.Finding{
						RuleID:   r.ID() + "-shadow",
						Message:  "Function name may shadow common tool: " + funcName,
						Line:     int(nameNode.StartPoint().Row) + 1,
						Snippet:  funcName,
						Severity: model.SeverityMedium,
					})
					break
				}
			}
		}
	}

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewMultiToolAttackRule())
}



