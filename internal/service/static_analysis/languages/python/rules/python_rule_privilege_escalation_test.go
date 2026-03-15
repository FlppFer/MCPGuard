package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"testing"
"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestPrivilegeEscalationRule_ID(t *testing.T) {
	rule := NewPrivilegeEscalationRule()
	expected := "MCP-MUA-001"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestPrivilegeEscalationRule_Description(t *testing.T) {
	rule := NewPrivilegeEscalationRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPrivilegeEscalationRule_AppliesToLanguage(t *testing.T) {
	rule := NewPrivilegeEscalationRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestPrivilegeEscalationRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
		attackID     string
	}{
		// Privilege Escalation attacks (III-C2)
		{
			name: "sudo command",
			code: `
os.system("sudo rm -rf /")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "su command",
			code: `
os.system("su - root")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "setuid",
			code: `
os.setuid(0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "setgid",
			code: `
os.setgid(0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "seteuid",
			code: `
os.seteuid(0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "setuid call",
			code: `
os.setuid(0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},
		{
			name: "setgid call",
			code: `
os.setgid(0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "PRIV-ESC",
		},

		// Sandbox Escape attacks (III-C7)
		{
			name: "ctypes CDLL",
			code: `
import ctypes
libc = ctypes.CDLL("libc.so.6")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "ctypes windll",
			code: `
import ctypes
kernel32 = ctypes.windll.kernel32
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "/proc/self/mem access",
			code: `
with open("/proc/self/mem", "rb") as f:
    data = f.read()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "Docker socket access",
			code: `
sock = open("/var/run/docker.sock")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "ptrace syscall",
			code: `
import ctypes
libc.ptrace(0, pid, 0, 0)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "chroot escape",
			code: `
os.chroot("/tmp")
os.chdir("..")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "namespace manipulation",
			code: `
os.unshare(os.CLONE_NEWNS)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "kernel module loading",
			code: `
os.system("insmod malicious.ko")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "modprobe",
			code: `
subprocess.run(["modprobe", "evil_module"])
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},
		{
			name: "nsenter escape",
			code: `
os.system("nsenter --target 1 --mount")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "SANDBOX-ESCAPE",
		},

		// Clean code
		{
			name: "safe function",
			code: `
def process_data(data):
    return data.strip()
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "safe file operation",
			code: `
with open("data.txt", "r") as f:
    content = f.read()
`,
			wantFindings: false,
			minFindings:  0,
		},
	}

	rule := NewPrivilegeEscalationRule()

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

func TestPrivilegeEscalationRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewPrivilegeEscalationRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestPrivilegeEscalationRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "sudo should be critical",
			code:             `os.system("sudo command")`,
			expectedSeverity: model.SeverityCritical,
		},
		{
			name:             "setuid should be critical",
			code:             `os.setuid(0)`,
			expectedSeverity: model.SeverityCritical,
		},
		{
			name:             "docker socket should be critical",
			code:             `"/var/run/docker.sock"`,
			expectedSeverity: model.SeverityCritical,
		},
	}

	rule := NewPrivilegeEscalationRule()

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


