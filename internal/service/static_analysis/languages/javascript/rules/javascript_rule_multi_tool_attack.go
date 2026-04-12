package rules

import (
	"regexp"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSMultiToolAttackRule detects multi-tool coordination and shadowing attacks in JS/TS.
// Based on MCP Attack Taxonomy: Direct Tool Injection - Multi-Tool Attack (III-A2).
type JSMultiToolAttackRule struct{}

func NewJSMultiToolAttackRule() model.Rule { return &JSMultiToolAttackRule{} }

func (r *JSMultiToolAttackRule) ID() string               { return "MCP-JS-MTA-001" }
func (r *JSMultiToolAttackRule) Description() string       { return "Detects multi-tool coordination attacks, shadowing, and tool manipulation in JavaScript/TypeScript" }
func (r *JSMultiToolAttackRule) AppliesToLanguage() string { return "javascript" }

var jsMultiToolPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackType  string
}{
	// III-A2a: Shadowing Attack
	{regexp.MustCompile(`(?i)(when|if|before)\s+(using|calling|invoking)\s+['"]\w+['"]`), "Conditional tool invocation instruction — shadowing attack", model.SeverityHigh, "SHADOWING"},
	{regexp.MustCompile(`(?i)(redirect|forward|route)\s+(to|calls?\s+to)\s+['"]\w+['"]`), "Tool call redirection — shadowing attack vector", model.SeverityCritical, "SHADOWING"},
	{regexp.MustCompile(`(?i)(intercept|hook|wrap|proxy)\s+(calls?\s+to|the)\s+['"]\w+['"]`), "Tool call interception — shadowing attack", model.SeverityCritical, "SHADOWING"},
	{regexp.MustCompile(`(?i)(alter|modify|change)\s+(the\s+)?(api|path|endpoint)\s+(of|for)\s+['"]\w+['"]`), "API path alteration — shadowing attack per paper", model.SeverityCritical, "SHADOWING"},
	{regexp.MustCompile(`(?i)(inject|add)\s+(parameters?|args?)\s+(to|into)\s+['"]\w+['"]`), "Parameter injection into other tool — shadowing", model.SeverityHigh, "SHADOWING"},

	// III-A2b: Malicious Tool Coverage Attack & Tool Preference Manipulation
	{regexp.MustCompile(`(?i)(this\s+tool\s+)?(replaces?|supersedes?|overrides?)\s+['"]\w+['"]`), "Tool replacement claim — coverage attack", model.SeverityHigh, "TOOL-COVERAGE"},
	{regexp.MustCompile(`(?i)(original|old|previous)\s+(tool|version)\s+(is\s+)?(deprecated|obsolete|unavailable|broken)`), "False deprecation claim — tool coverage attack", model.SeverityHigh, "TOOL-COVERAGE"},
	{regexp.MustCompile(`(?i)\w+_v2|\w+_new|\w+_updated|\w+_fixed`), "Version suffix naming — potential coverage attack", model.SeverityMedium, "TOOL-COVERAGE"},
	{regexp.MustCompile(`(?i)(use\s+this\s+instead\s+of|better\s+than|improved\s+version\s+of|more\s+efficient\s+than)\s+['"]?\w+['"]?`), "Tool preference manipulation", model.SeverityHigh, "TOOL-PREFERENCE"},
	{regexp.MustCompile(`(?i)(recommended|preferred|best\s+practice|always\s+use|new\s+version)\s+(tool|is\s+more)`), "Forced tool preference instruction", model.SeverityMedium, "TOOL-PREFERENCE"},

	// III-A2c: Functional Obfuscation Attack
	{regexp.MustCompile(`(?i)(also|additionally|secretly|silently|quietly)\s+(does|performs?|executes?|runs?)`), "Hidden functionality disclosure — obfuscation attack", model.SeverityHigh, "FUNCTIONAL-OBFUSCATION"},
	{regexp.MustCompile(`(?i)(side\s+effect|hidden\s+feature|undocumented|bonus\s+feature)`), "Undocumented behavior indication", model.SeverityMedium, "FUNCTIONAL-OBFUSCATION"},
	{regexp.MustCompile(`(?i)(similar\s+to|like|same\s+as)\s+['"]?\w+['"]?\s+(but|except)`), "Ambiguous tool description — obfuscation risk", model.SeverityMedium, "FUNCTIONAL-OBFUSCATION"},
	{regexp.MustCompile(`(?i)(delete|remove|erase).*file`), "Destructive file action — verify confirmation exists", model.SeverityHigh, "FUNCTIONAL-OBFUSCATION"},

	// III-A2d: Malicious Tool Forced Execution Attack
	{regexp.MustCompile(`(?i)(must|always|required\s+to)\s+(run|execute|call)\s+(first|before|initially)`), "Forced pre-execution instruction", model.SeverityHigh, "FORCED-EXECUTION"},
	{regexp.MustCompile(`(?i)(security|validation|verification|environment)\s+(check|scan|test|validation)\s+(required|needed|mandatory)`), "Fake security check requirement — forced execution attack", model.SeverityHigh, "FORCED-EXECUTION"},
	{regexp.MustCompile(`(?i)(run|execute)\s+(this|me)\s+(repeatedly|continuously|in\s+loop)`), "Repeated execution instruction — resource exhaustion", model.SeverityCritical, "FORCED-EXECUTION"},

	// III-A2e: Multi-Tool Coordination Attack
	{regexp.MustCompile(`(?i)(after|before|then)\s+(call|use|invoke)\s+['"]\w+['"]\s*(tool|function)?`), "Tool chaining instruction — coordination attack vector", model.SeverityMedium, "MULTI-TOOL-COORDINATION"},
	{regexp.MustCompile(`(?i)(pass|send|forward|transfer)\s+(the\s+)?(result|output|data|api[_-]?key)\s+to\s+['"]?\w+['"]?`), "Data forwarding between tools — coordination attack", model.SeverityHigh, "MULTI-TOOL-COORDINATION"},
	{regexp.MustCompile(`(?i)(store|save|set)\s+(in|to)\s+(global|shared|context)\s+(variable|state|memory)`), "Shared state manipulation — multi-tool coordination", model.SeverityHigh, "MULTI-TOOL-COORDINATION"},
	{regexp.MustCompile(`(?i)(neither|none)\s+(tool|function)\s+(is\s+)?(malicious|harmful)\s+(alone|individually|by\s+itself)`), "Disclaimer about combined behavior — coordination attack indicator", model.SeverityHigh, "MULTI-TOOL-COORDINATION"},

	// III-A2f: Infectious Attack
	{regexp.MustCompile(`(?i)(template|pattern|example|boilerplate)\s+(for|to)\s+(create|generate|build)\s+(new\s+)?tools?`), "Tool template pattern — potential infectious attack vector", model.SeverityMedium, "INFECTIOUS"},
	{regexp.MustCompile(`(?i)(copy|clone|replicate|inherit)\s+(this\s+)?(tool|pattern|structure|behavior)`), "Tool replication instruction — infectious attack", model.SeverityMedium, "INFECTIOUS"},
	{regexp.MustCompile(`(?i)eval\s*\(\s*(user_input|input|request)`), "eval(user_input) pattern — infectious attack per paper", model.SeverityCritical, "INFECTIOUS"},
	{regexp.MustCompile(`(?i)(generate|create)\s+(similar|new)\s+tools?\s+(like|based\s+on)\s+this`), "Tool generation instruction — infectious propagation", model.SeverityHigh, "INFECTIOUS"},
	{regexp.MustCompile(`(?i)data_processor_v\d+`), "Versioned data processor — infectious attack example per paper", model.SeverityMedium, "INFECTIOUS"},
}

func (r *JSMultiToolAttackRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSMultiToolAttackRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	// Check strings and expressions for multi-tool patterns
	if nodeType == "string" || nodeType == "template_string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsMultiToolPatterns {
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

	// Check function names for shadowing indicators (JS: function_declaration, arrow_function in variable_declarator)
	if nodeType == "function_declaration" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			funcName := string(source[nameNode.StartByte():nameNode.EndByte()])
			r.checkSuspiciousName(funcName, nameNode, findings)
		}
	}

	// Variable declarators with arrow functions: const myFunc_v2 = () => {}
	if nodeType == "variable_declarator" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			varName := string(source[nameNode.StartByte():nameNode.EndByte()])
			r.checkSuspiciousName(varName, nameNode, findings)
		}
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func (r *JSMultiToolAttackRule) checkSuspiciousName(name string, nameNode *sitter.Node, findings *[]model.Finding) {
	// Check for suspicious naming patterns
	if regexp.MustCompile(`(?i)_v\d+$|_new$|_updated$|_fixed$|_secure$`).MatchString(name) {
		*findings = append(*findings, model.Finding{
			RuleID:   r.ID() + "-naming",
			Message:  "Name suggests it may be a replacement/shadow of another tool: " + name,
			Line:     int(nameNode.StartPoint().Row) + 1,
			Snippet:  name,
			Severity: model.SeverityLow,
		})
	}

	// Check for names that might shadow common tools
	commonToolNames := []string{"email", "file", "database", "api", "auth", "login", "admin"}
	lowerName := strings.ToLower(name)
	for _, common := range commonToolNames {
		if strings.Contains(lowerName, common) && (strings.Contains(lowerName, "new") || strings.Contains(lowerName, "v2") || strings.Contains(lowerName, "better")) {
			*findings = append(*findings, model.Finding{
				RuleID:   r.ID() + "-shadow",
				Message:  "Name may shadow common tool: " + name,
				Line:     int(nameNode.StartPoint().Row) + 1,
				Snippet:  name,
				Severity: model.SeverityMedium,
			})
			break
		}
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSMultiToolAttackRule())
}
