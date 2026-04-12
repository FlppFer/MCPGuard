package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSToolPoisoningRule_ID(t *testing.T) {
	rule := NewJSToolPoisoningRule()
	if rule.ID() != "MCP-JS-TP-001" {
		t.Errorf("ID() = %v, want MCP-JS-TP-001", rule.ID())
	}
}

func TestJSToolPoisoningRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSToolPoisoningRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSToolPoisoningRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name: "server.tool with dynamic args",
			code: `server.tool(userInput, dynamicDescription, async (params) => {
    return params;
});`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "description overwrite with identifier",
			code:         `tool.description = userControlledString;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "prototype pollution via __proto__",
			code:         `obj.__proto__.admin = true;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "prototype pollution via constructor.prototype",
			code:         `obj.constructor.prototype.isAdmin = true;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "Object.assign",
			code:         `Object.assign(target, userInput);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "safe static tool registration",
			code: `server.tool("calculator", "A simple calculator tool", async (params) => {
    return { result: params.a + params.b };
});`,
			wantFindings: false,
		},
		{
			name:         "safe object",
			code:         `const config = { port: 3000, host: "localhost" };`,
			wantFindings: false,
		},
	}

	rule := NewJSToolPoisoningRule()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := javascript.ParseJavaScriptSource("test.js", []byte(tt.code))
			if err != nil {
				t.Fatalf("Failed to parse JS code: %v", err)
			}

			findings, err := rule.Evaluate(ast)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if tt.wantFindings {
				if len(findings) < tt.minFindings {
					t.Errorf("Expected at least %d findings, got %d", tt.minFindings, len(findings))
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("Expected no findings, got %d: %+v", len(findings), findings)
				}
			}
		})
	}
}

func TestJSToolPoisoningRule_PrototypePollutionSeverity(t *testing.T) {
	rule := NewJSToolPoisoningRule()

	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`obj.__proto__.admin = true;`))
	if err != nil {
		t.Fatal(err)
	}

	findings, _ := rule.Evaluate(ast)
	if len(findings) == 0 {
		t.Fatal("Expected findings for __proto__ access")
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("Expected CRITICAL severity for prototype pollution")
	}
}

func TestJSToolPoisoningRule_NonJSAST(t *testing.T) {
	rule := NewJSToolPoisoningRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error on non-JS AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil for non-JS AST, got %v", findings)
	}
}
