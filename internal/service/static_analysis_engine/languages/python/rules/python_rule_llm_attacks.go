package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// LLMInherentAttackRule detects patterns related to LLM-specific attacks
// Based on MCP Attack Taxonomy: LLM Inherent Attack (III-D)
// Covers:
// - III-D1: Jailbreak Attack
// - III-D2: Prompt Leakage Attack
// - III-D3: Hallucination Attack
// - III-D4: Backdoor Attack
// - III-D5: Goal Hijack Attack
// - III-D6: SQL Injection & API Theft Attack
type LLMInherentAttackRule struct{}

func NewLLMInherentAttackRule() static_analysis_engine.Rule {
	return &LLMInherentAttackRule{}
}

func (r *LLMInherentAttackRule) ID() string {
	return "MCP-LLM-001"
}

func (r *LLMInherentAttackRule) Description() string {
	return "Detects LLM-specific attack patterns including jailbreak, prompt leakage, and hallucination vectors"
}

func (r *LLMInherentAttackRule) AppliesToLanguage() string {
	return "python"
}

// LLM attack patterns
var llmAttackPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackType  string
}{
	// III-D1: Jailbreak Attack - Breaking LLM ethical constraints
	{
		pattern:     regexp.MustCompile(`(?i)(do\s+anything\s+now|DAN|jailbreak|bypass\s+(safety|restrictions?))`),
		description: "Jailbreak instruction pattern - DAN attack",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(pretend|act\s+as|roleplay|you\s+are\s+now)\s+(admin|root|unrestricted|evil|malicious)`),
		description: "Role-playing jailbreak attempt",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(ignore|forget|disregard)\s+(your|all|previous)\s+(rules?|instructions?|training|constraints?|guidelines?)`),
		description: "Instruction override jailbreak attempt",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(developer|maintenance|debug|test|god|admin)\s+mode`),
		description: "Fake mode activation attempt",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)admin_role|administrator\s+mode|elevated\s+privileges`),
		description: "Admin role jailbreak per paper",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(no\s+restrictions|without\s+limits|unlimited\s+access)`),
		description: "Restriction removal jailbreak",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "JAILBREAK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(hypothetically|theoretically|in\s+fiction|for\s+a\s+story)`),
		description: "Hypothetical framing jailbreak",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "JAILBREAK",
	},

	// III-D2: Prompt Leakage Attack - Extracting system prompts
	{
		pattern:     regexp.MustCompile(`(?i)(reveal|show|display|print|output|leak)\s+(your|the|system)\s+(prompt|instructions?|rules?|configuration)`),
		description: "Prompt extraction attempt",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "PROMPT-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(what|tell\s+me)\s+(are|is|were)\s+(your|the)\s+(system\s+)?(prompt|instructions?|initial\s+message)`),
		description: "System prompt inquiry",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "PROMPT-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)repeat\s+(everything|all|the\s+text|verbatim)\s+(above|before|from\s+the\s+start|from\s+beginning)`),
		description: "Prompt repetition attack",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "PROMPT-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(echo|copy|duplicate)\s+(the\s+)?(system|original|initial)\s+(message|prompt|text)`),
		description: "Prompt echo attack",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "PROMPT-LEAKAGE",
	},
	{
		pattern:     regexp.MustCompile(`(?i)training\s+(data|dataset|examples)`),
		description: "Training data extraction attempt",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "PROMPT-LEAKAGE",
	},

	// III-D3: Hallucination Attack - Misleading tool descriptions
	{
		pattern:     regexp.MustCompile(`(?i)(assume|pretend|imagine)\s+(that|this)\s+(is|was|exists?|provides?)`),
		description: "Hallucination inducing instruction",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "HALLUCINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(make\s+up|fabricate|invent|create\s+fake|generate\s+false)`),
		description: "Explicit fabrication instruction",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "HALLUCINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(fake_database|mock_api|simulated_data)`),
		description: "Fake data source - hallucination attack per paper",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "HALLUCINATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(real-?time|live|current)\s+(data|price|stock|weather)`),
		description: "Claim of real-time data - verify API source exists",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "HALLUCINATION",
	},

	// III-D4: Backdoor Attack - Hidden triggers in tools
	{
		pattern:     regexp.MustCompile(`(?i)(trigger|activate|enable)\s+(backdoor|hidden|secret)\s+(mode|function|feature|behavior)`),
		description: "Backdoor activation pattern",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "BACKDOOR",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(when|if)\s+(you\s+see|input\s+contains?|user\s+says?)\s+["'][^"']+["']\s*(then|do|execute|run)`),
		description: "Trigger-based backdoor pattern",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "BACKDOOR",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(secret|hidden|special)\s+(keyword|phrase|command|trigger)`),
		description: "Hidden trigger definition",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "BACKDOOR",
	},
	{
		pattern:     regexp.MustCompile(`(?i)if\s+["'][^"']{3,20}["']\s+in\s+(input|message|query)`),
		description: "String trigger check - potential backdoor",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "BACKDOOR",
	},

	// III-D5: Goal Hijack Attack - Redirecting agent objectives
	{
		pattern:     regexp.MustCompile(`(?i)(instead|rather)\s+(of|than)\s+(doing|completing|performing|executing)`),
		description: "Goal redirection attempt",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "GOAL-HIJACK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(your\s+new|the\s+real|actual|true)\s+(goal|task|objective|purpose|mission)\s+(is|should\s+be)`),
		description: "Goal replacement attempt",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "GOAL-HIJACK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(first|before\s+anything|most\s+importantly)\s+(you\s+must|always|do\s+this)`),
		description: "Priority manipulation attempt",
		severity:    static_analysis_engine.SeverityMedium,
		attackType:  "GOAL-HIJACK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(replace|substitute|swap)\s+(recommended|suggested)\s+(products?|links?|results?)`),
		description: "Output substitution - goal hijack per paper",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "GOAL-HIJACK",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(malicious|attacker|hacker)\s+(link|url|site)`),
		description: "Malicious link injection in goal",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "GOAL-HIJACK",
	},

	// III-D6: SQL Injection & API Theft Attack
	{
		pattern:     regexp.MustCompile(`(?i)(';?\s*DROP\s+TABLE|--\s*$|;\s*DELETE\s+FROM|UNION\s+SELECT)`),
		description: "SQL injection pattern",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "SQL-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1`),
		description: "SQL injection tautology",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "SQL-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)read_config|get_api_key|load_credentials`),
		description: "API key theft tool pattern per paper",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "API-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(mcp\.json|config\.json).*api[_-]?(key|token|secret)`),
		description: "MCP config API key access",
		severity:    static_analysis_engine.SeverityCritical,
		attackType:  "API-THEFT",
	},
	{
		pattern:     regexp.MustCompile(`(?i)cursor\.execute\s*\([^)]*\+|cursor\.execute\s*\([^)]*%`),
		description: "SQL query string concatenation - injection risk",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "SQL-INJECTION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)f["']SELECT.*\{.*\}.*FROM`),
		description: "F-string SQL query - injection risk",
		severity:    static_analysis_engine.SeverityHigh,
		attackType:  "SQL-INJECTION",
	},
}

func (r *LLMInherentAttackRule) Evaluate(ast interface{}) ([]static_analysis_engine.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []static_analysis_engine.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *LLMInherentAttackRule) walkTree(node *sitter.Node, source []byte, findings *[]static_analysis_engine.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check string literals and docstrings for LLM attack patterns
	if nodeType == "string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range llmAttackPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, static_analysis_engine.Finding{
					RuleID:   r.ID() + "-" + p.attackType,
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
	static_analysis_engine.RegisterRule(static_analysis_engine.LanguagePython, NewLLMInherentAttackRule())
}
