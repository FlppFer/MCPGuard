package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSCommandInjectionRule_ID(t *testing.T) {
	rule := NewJSCommandInjectionRule()
	if rule.ID() != "MCP-JS-CMD-001" {
		t.Errorf("ID() = %v, want MCP-JS-CMD-001", rule.ID())
	}
}

func TestJSCommandInjectionRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSCommandInjectionRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSCommandInjectionRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "exec call",
			code:         `exec('ls -la');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "execSync call",
			code:         `execSync('rm -rf /tmp');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "eval call",
			code:         `eval(userInput);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "new Function constructor",
			code:         `const fn = new Function('a', 'return a + 1');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "require child_process",
			code:         `const cp = require('child_process');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "member exec call",
			code: `const cp = require('child_process');
cp.exec(userInput);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe function call",
			code:         `console.log("hello");`,
			wantFindings: false,
		},
		{
			name:         "safe arithmetic",
			code:         `const result = a + b;`,
			wantFindings: false,
		},
	}

	rule := NewJSCommandInjectionRule()

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

func TestJSCommandInjectionRule_EvalSeverity(t *testing.T) {
	rule := NewJSCommandInjectionRule()

	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`eval(code);`))
	if err != nil {
		t.Fatal(err)
	}

	findings, _ := rule.Evaluate(ast)
	if len(findings) == 0 {
		t.Fatal("Expected findings for eval()")
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("Expected severity %s, got %s", model.SeverityCritical, findings[0].Severity)
	}
}

func TestJSCommandInjectionRule_NonJSAST(t *testing.T) {
	rule := NewJSCommandInjectionRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error on non-JS AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil for non-JS AST, got %v", findings)
	}
}
