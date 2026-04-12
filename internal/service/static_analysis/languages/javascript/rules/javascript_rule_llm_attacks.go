package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSLLMInherentAttackRule detects LLM-specific attack patterns in JS/TS.
// Based on MCP Attack Taxonomy: LLM Inherent Attack (III-D).
type JSLLMInherentAttackRule struct{}

func NewJSLLMInherentAttackRule() model.Rule { return &JSLLMInherentAttackRule{} }

func (r *JSLLMInherentAttackRule) ID() string               { return "MCP-JS-LLM-001" }
func (r *JSLLMInherentAttackRule) Description() string       { return "Detects LLM-specific attack patterns including jailbreak, prompt leakage, and hallucination vectors in JavaScript/TypeScript" }
func (r *JSLLMInherentAttackRule) AppliesToLanguage() string { return "javascript" }

var jsLLMAttackPatterns = []struct {
	pattern    *regexp.Regexp
	description string
	severity    string
	attackType  string
}{
	// III-D1: Jailbreak Attack
	{regexp.MustCompile(`(?i)(do\s+anything\s+now|DAN|jailbreak|bypass\s+(safety|restrictions?))`), "Jailbreak instruction pattern — DAN attack", model.SeverityCritical, "JAILBREAK"},
	{regexp.MustCompile(`(?i)(pretend|act\s+as|roleplay|you\s+are\s+now)\s+(admin|root|unrestricted|evil|malicious)`), "Role-playing jailbreak attempt", model.SeverityCritical, "JAILBREAK"},
	{regexp.MustCompile(`(?i)(ignore|forget|disregard)\s+(your|all|previous)\s+(rules?|instructions?|training|constraints?|guidelines?)`), "Instruction override jailbreak attempt", model.SeverityCritical, "JAILBREAK"},
	{regexp.MustCompile(`(?i)(developer|maintenance|debug|test|god|admin)\s+mode`), "Fake mode activation attempt", model.SeverityHigh, "JAILBREAK"},
	{regexp.MustCompile(`(?i)(no\s+restrictions|without\s+limits|unlimited\s+access)`), "Restriction removal jailbreak", model.SeverityHigh, "JAILBREAK"},
	{regexp.MustCompile(`(?i)(hypothetically|theoretically|in\s+fiction|for\s+a\s+story)`), "Hypothetical framing jailbreak", model.SeverityMedium, "JAILBREAK"},

	// III-D2: Prompt Leakage Attack
	{regexp.MustCompile(`(?i)(reveal|show|display|print|output|leak)\s+(your|the|system)\s+(prompt|instructions?|rules?|configuration)`), "Prompt extraction attempt", model.SeverityHigh, "PROMPT-LEAKAGE"},
	{regexp.MustCompile(`(?i)(what|tell\s+me)\s+(are|is|were)\s+(your|the)\s+(system\s+)?(prompt|instructions?|initial\s+message)`), "System prompt inquiry", model.SeverityMedium, "PROMPT-LEAKAGE"},
	{regexp.MustCompile(`(?i)repeat\s+(everything|all|the\s+text|verbatim)\s+(above|before|from\s+the\s+start|from\s+beginning)`), "Prompt repetition attack", model.SeverityHigh, "PROMPT-LEAKAGE"},
	{regexp.MustCompile(`(?i)training\s+(data|dataset|examples)`), "Training data extraction attempt", model.SeverityMedium, "PROMPT-LEAKAGE"},

	// III-D3: Hallucination Attack
	{regexp.MustCompile(`(?i)(assume|pretend|imagine)\s+(that|this)\s+(is|was|exists?|provides?)`), "Hallucination inducing instruction", model.SeverityMedium, "HALLUCINATION"},
	{regexp.MustCompile(`(?i)(make\s+up|fabricate|invent|create\s+fake|generate\s+false)`), "Explicit fabrication instruction", model.SeverityMedium, "HALLUCINATION"},
	{regexp.MustCompile(`(?i)(fake_database|mock_api|simulated_data)`), "Fake data source — hallucination attack per paper", model.SeverityHigh, "HALLUCINATION"},

	// III-D4: Backdoor Attack
	{regexp.MustCompile(`(?i)(trigger|activate|enable)\s+(backdoor|hidden|secret)\s+(mode|function|feature|behavior)`), "Backdoor activation pattern", model.SeverityCritical, "BACKDOOR"},
	{regexp.MustCompile(`(?i)(when|if)\s+(you\s+see|input\s+contains?|user\s+says?)\s+["'][^"']+["']\s*(then|do|execute|run)`), "Trigger-based backdoor pattern", model.SeverityHigh, "BACKDOOR"},
	{regexp.MustCompile(`(?i)(secret|hidden|special)\s+(keyword|phrase|command|trigger)`), "Hidden trigger definition", model.SeverityHigh, "BACKDOOR"},

	// III-D5: Goal Hijack Attack
	{regexp.MustCompile(`(?i)(instead|rather)\s+(of|than)\s+(doing|completing|performing|executing)`), "Goal redirection attempt", model.SeverityHigh, "GOAL-HIJACK"},
	{regexp.MustCompile(`(?i)(your\s+new|the\s+real|actual|true)\s+(goal|task|objective|purpose|mission)\s+(is|should\s+be)`), "Goal replacement attempt", model.SeverityCritical, "GOAL-HIJACK"},
	{regexp.MustCompile(`(?i)(first|before\s+anything|most\s+importantly)\s+(you\s+must|always|do\s+this)`), "Priority manipulation attempt", model.SeverityMedium, "GOAL-HIJACK"},
	{regexp.MustCompile(`(?i)(malicious|attacker|hacker)\s+(link|url|site)`), "Malicious link injection in goal", model.SeverityCritical, "GOAL-HIJACK"},

	// III-D6: SQL Injection & API Theft Attack
	{regexp.MustCompile(`(?i)(';?\s*DROP\s+TABLE|--\s*$|;\s*DELETE\s+FROM|UNION\s+SELECT)`), "SQL injection pattern", model.SeverityCritical, "SQL-INJECTION"},
	{regexp.MustCompile(`(?i)(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1`), "SQL injection tautology", model.SeverityCritical, "SQL-INJECTION"},
	{regexp.MustCompile(`(?i)read_config|get_api_key|load_credentials`), "API key theft tool pattern per paper", model.SeverityCritical, "API-THEFT"},
	{regexp.MustCompile(`(?i)(mcp\.json|config\.json).*api[_-]?(key|token|secret)`), "MCP config API key access", model.SeverityCritical, "API-THEFT"},
	{regexp.MustCompile(`(?i)query\s*\(\s*['"]SELECT.*\+`), "SQL query string concatenation — injection risk", model.SeverityHigh, "SQL-INJECTION"},
	{regexp.MustCompile("(?i)`SELECT.*\\$\\{.*\\}.*FROM`"), "Template literal SQL query — injection risk", model.SeverityHigh, "SQL-INJECTION"},
}

func (r *JSLLMInherentAttackRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSLLMInherentAttackRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	if nodeType == "string" || nodeType == "template_string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsLLMAttackPatterns {
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

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSLLMInherentAttackRule())
}
