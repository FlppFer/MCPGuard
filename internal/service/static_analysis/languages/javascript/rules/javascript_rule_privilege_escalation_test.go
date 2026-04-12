package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSPrivilegeEscalationRule_ID(t *testing.T) {
	rule := NewJSPrivilegeEscalationRule()
	if rule.ID() != "MCP-JS-PE-001" {
		t.Errorf("ID() = %v, want MCP-JS-PE-001", rule.ID())
	}
}

func TestJSPrivilegeEscalationRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSPrivilegeEscalationRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSPrivilegeEscalationRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "sudo command",
			code:         `const cmd = "sudo rm -rf /";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "process.setuid",
			code:         `process.setuid(0);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "docker socket access",
			code:         `const sock = "/var/run/docker.sock";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "path traversal",
			code:         `const path = "../../etc/passwd";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "require child_process (privilege import)",
			code:         `const cp = require('child_process');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "native addon loading",
			code:         `process.dlopen(module, '/path/to/addon.node');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "vm.runInThisContext",
			code:         `vm.runInThisContext(code);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "nsenter escape",
			code:         `const cmd = "nsenter --target 1 --mount";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; const arr = [1, 2, 3];`,
			wantFindings: false,
		},
	}

	rule := NewJSPrivilegeEscalationRule()
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

func TestJSPrivilegeEscalationRule_DockerSocketSeverity(t *testing.T) {
	rule := NewJSPrivilegeEscalationRule()
	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`const sock = "/var/run/docker.sock";`))
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
		t.Error("Expected CRITICAL severity for docker.sock access")
	}
}

func TestJSPrivilegeEscalationRule_NonJSAST(t *testing.T) {
	rule := NewJSPrivilegeEscalationRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil, got %v", findings)
	}
}
