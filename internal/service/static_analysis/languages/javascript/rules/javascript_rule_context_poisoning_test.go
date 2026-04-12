package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSContextPoisoningRule_ID(t *testing.T) {
	rule := NewJSContextPoisoningRule()
	if rule.ID() != "MCP-JS-CTX-001" {
		t.Errorf("ID() = %v, want MCP-JS-CTX-001", rule.ID())
	}
}

func TestJSContextPoisoningRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSContextPoisoningRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSContextPoisoningRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "context modification with input",
			code:         `context["key"] = input;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "session state modification",
			code:         `session["user"] = "admin";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "globalThis modification",
			code:         `globalThis["secret"] = value;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "Object.defineProperty",
			code:         `Object.defineProperty(target, 'prop', { value: 42 });`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "Reflect.set",
			code:         `Reflect.set(target, 'key', value);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; const name = "safe";`,
			wantFindings: false,
		},
	}

	rule := NewJSContextPoisoningRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := javascript.ParseJavaScriptSource("test.js", []byte(tt.code))
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}
			findings, err := rule.Evaluate(ast)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if tt.wantFindings && len(findings) < tt.minFindings {
				t.Errorf("Expected at least %d findings, got %d", tt.minFindings, len(findings))
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Errorf("Expected no findings, got %d: %+v", len(findings), findings)
			}
		})
	}
}

func TestJSContextPoisoningRule_NonJSAST(t *testing.T) {
	rule := NewJSContextPoisoningRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil, got %v", findings)
	}
}
