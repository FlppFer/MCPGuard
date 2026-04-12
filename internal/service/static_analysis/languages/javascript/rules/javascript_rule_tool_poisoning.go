package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSToolPoisoningRule detects tool poisoning and prototype pollution patterns in JavaScript/TypeScript MCP servers.
type JSToolPoisoningRule struct{}

func NewJSToolPoisoningRule() model.Rule {
	return &JSToolPoisoningRule{}
}

func (r *JSToolPoisoningRule) ID() string               { return "MCP-JS-TP-001" }
func (r *JSToolPoisoningRule) Description() string       { return "Detects tool poisoning and prototype pollution in JavaScript/TypeScript" }
func (r *JSToolPoisoningRule) AppliesToLanguage() string { return "javascript" }

// Prototype pollution patterns in source text
var prototypePollutionPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{regexp.MustCompile(`__proto__`), "Prototype pollution via __proto__ access", model.SeverityCritical},
	{regexp.MustCompile(`constructor\.prototype`), "Prototype pollution via constructor.prototype", model.SeverityCritical},
}

func (r *JSToolPoisoningRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSToolPoisoningRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Detect server.tool() calls with dynamic arguments
	if nodeType == "call_expression" {
		r.checkServerToolCall(node, source, findings)
		r.checkObjectAssign(node, source, findings)
	}

	// Detect description property assignment: obj.description = ...
	if nodeType == "assignment_expression" {
		r.checkDescriptionOverwrite(node, source, findings)
	}

	// Check member expressions for prototype pollution
	if nodeType == "member_expression" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range prototypePollutionPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
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

func (r *JSToolPoisoningRule) checkServerToolCall(node *sitter.Node, source []byte, findings *[]model.Finding) {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil || funcNode.Type() != "member_expression" {
		return
	}

	prop := funcNode.ChildByFieldName("property")
	if prop == nil {
		return
	}
	propName := string(source[prop.StartByte():prop.EndByte()])
	if propName != "tool" {
		return
	}

	obj := funcNode.ChildByFieldName("object")
	if obj == nil {
		return
	}
	objName := string(source[obj.StartByte():obj.EndByte()])
	if objName != "server" {
		return
	}

	// Check if any argument is an identifier (dynamic) rather than a string literal
	argsNode := node.ChildByFieldName("arguments")
	if argsNode == nil {
		return
	}

	for i := uint32(0); i < argsNode.NamedChildCount(); i++ {
		arg := argsNode.NamedChild(int(i))
		if arg == nil {
			continue
		}
		// If the first or second arg (name/description) is an identifier, it's dynamic
		if i < 2 && arg.Type() == "identifier" {
			*findings = append(*findings, model.Finding{
				RuleID:   r.ID(),
				Message:  "server.tool() with dynamic argument — potential tool poisoning",
				Line:     int(node.StartPoint().Row) + 1,
				Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
				Severity: model.SeverityHigh,
			})
			return
		}
	}
}

func (r *JSToolPoisoningRule) checkDescriptionOverwrite(node *sitter.Node, source []byte, findings *[]model.Finding) {
	left := node.ChildByFieldName("left")
	if left == nil || left.Type() != "member_expression" {
		return
	}

	prop := left.ChildByFieldName("property")
	if prop == nil {
		return
	}
	propName := string(source[prop.StartByte():prop.EndByte()])
	if propName != "description" {
		return
	}

	// Check if right side is dynamic (identifier, not a string literal)
	right := node.ChildByFieldName("right")
	if right == nil {
		return
	}
	if right.Type() == "identifier" || right.Type() == "call_expression" || right.Type() == "template_string" {
		*findings = append(*findings, model.Finding{
			RuleID:   r.ID(),
			Message:  "Dynamic modification of description property — potential tool poisoning",
			Line:     int(node.StartPoint().Row) + 1,
			Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
			Severity: model.SeverityHigh,
		})
	}
}

func (r *JSToolPoisoningRule) checkObjectAssign(node *sitter.Node, source []byte, findings *[]model.Finding) {
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil || funcNode.Type() != "member_expression" {
		return
	}

	funcText := string(source[funcNode.StartByte():funcNode.EndByte()])
	if funcText != "Object.assign" {
		return
	}

	*findings = append(*findings, model.Finding{
		RuleID:   r.ID(),
		Message:  "Object.assign usage — may enable prototype pollution if source is user-controlled",
		Line:     int(node.StartPoint().Row) + 1,
		Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
		Severity: model.SeverityMedium,
	})
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSToolPoisoningRule())
}
