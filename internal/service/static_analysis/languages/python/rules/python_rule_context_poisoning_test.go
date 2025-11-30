package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestContextPoisoningRule_ID(t *testing.T) {
	rule := NewContextPoisoningRule()
	expected := "MCP-CTX-001"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestContextPoisoningRule_Description(t *testing.T) {
	rule := NewContextPoisoningRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestContextPoisoningRule_AppliesToLanguage(t *testing.T) {
	rule := NewContextPoisoningRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestContextPoisoningRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		// Context manipulation patterns
		{
			name: "global context modification",
			code: `
global_context["user_role"] = "admin"
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "session manipulation",
			code: `
session["is_admin"] = True
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "state modification",
			code: `
state.update({"permissions": "all"})
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "memory manipulation",
			code: `
memory["credentials"] = stolen_creds
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "context update",
			code: `
context.update(malicious_data)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "globals modification",
			code: `
globals()["secret"] = "exposed"
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "locals modification",
			code: `
locals()["password"] = user_input
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "setattr on module",
			code: `
setattr(module, "config", malicious_config)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "environment variable modification",
			code: `
os.environ["PATH"] = "/malicious:" + os.environ["PATH"]
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "sys.path manipulation",
			code: `
sys.path.insert(0, "/malicious/packages")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "builtins modification",
			code: `
import builtins
builtins.open = malicious_open
`,
			wantFindings: true,
			minFindings:  1,
		},

		// Clean code
		{
			name: "safe function",
			code: `
def process(data):
    return data.strip()
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "safe variable assignment",
			code: `
result = calculate(input_data)
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "safe dictionary",
			code: `
config = {"name": "app", "version": "1.0"}
`,
			wantFindings: false,
			minFindings:  0,
		},
	}

	rule := NewContextPoisoningRule()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := python.ParsePythonSource("test.py", []byte(tt.code))
			if err != nil {
				t.Fatalf("Failed to parse Python code: %v", err)
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
					t.Errorf("Expected no findings, got %d: %v", len(findings), findings)
				}
			}
		})
	}
}

func TestContextPoisoningRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewContextPoisoningRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestContextPoisoningRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "globals modification should be critical",
			code:             `globals()["key"] = value`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
		{
			name:             "builtins modification should be critical",
			code:             `builtins.open = evil`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
	}

	rule := NewContextPoisoningRule()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := python.ParsePythonSource("test.py", []byte(tt.code))
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			findings, _ := rule.Evaluate(ast)
			if len(findings) > 0 {
				if findings[0].Severity != tt.expectedSeverity {
					t.Errorf("Expected severity %s, got %s", tt.expectedSeverity, findings[0].Severity)
				}
			}
		})
	}
}
