package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestCommandInjectionRule_ID(t *testing.T) {
	rule := NewCommandInjectionRule()
	expected := "MCP-DTI-002"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestCommandInjectionRule_Description(t *testing.T) {
	rule := NewCommandInjectionRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestCommandInjectionRule_AppliesToLanguage(t *testing.T) {
	rule := NewCommandInjectionRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestCommandInjectionRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
		checkRuleID  string
	}{
		{
			name: "os.system call",
			code: `
import os
os.system("ls -la")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "subprocess with shell=True",
			code: `
import subprocess
subprocess.run(cmd, shell=True)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "subprocess.Popen with shell=True",
			code: `
import subprocess
subprocess.Popen(command, shell=True)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "subprocess.call with shell=True",
			code: `
import subprocess
subprocess.call(["bash", "-c", cmd], shell=True)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "eval function",
			code: `
user_input = input()
eval(user_input)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "exec function",
			code: `
code = "print('hello')"
exec(code)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "os.popen",
			code: `
import os
os.popen("cat /etc/passwd")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "compile function",
			code: `
code = compile(source, "<string>", "exec")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "string formatting in command",
			code: `
import os
os.system(f"rm -rf {user_input}")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "backticks in shell command",
			code:         "import os\nos.system(\"echo $(whoami)\")",
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "pipe in command",
			code: `
import os
os.system("cat file | grep password")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "command chaining with semicolon",
			code: `
import os
os.system("ls; rm -rf /")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "command chaining with &&",
			code: `
import os
os.system("test && malicious_command")
`,
			wantFindings: true,
			minFindings:  1,
		},
	}

	rule := NewCommandInjectionRule()

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

func TestCommandInjectionRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewCommandInjectionRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestCommandInjectionRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "os.system should be high",
			code:             `os.system("cmd")`,
			expectedSeverity: static_analysis.SeverityHigh,
		},
		{
			name:             "eval should be critical",
			code:             `eval(user_input)`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
		{
			name:             "exec should be critical",
			code:             `exec(code)`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
	}

	rule := NewCommandInjectionRule()

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
