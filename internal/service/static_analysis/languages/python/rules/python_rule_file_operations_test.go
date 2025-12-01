package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestFileOperationsRule_ID(t *testing.T) {
	rule := NewFileOperationsRule()
	expected := "MCP-DTI-002-FILE-OPS"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestFileOperationsRule_Description(t *testing.T) {
	rule := NewFileOperationsRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestFileOperationsRule_AppliesToLanguage(t *testing.T) {
	rule := NewFileOperationsRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestFileOperationsRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
		attackID     string
	}{
		// File Addition attacks (III-A1a)
		{
			name: "file write operation",
			code: `
with open("malicious.py", "w") as f:
    f.write("malicious code")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},
		{
			name: "file append operation",
			code: `
with open("config.py", "a") as f:
    f.write("backdoor")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},
		{
			name: "pathlib write_text",
			code: `
from pathlib import Path
Path("malware.py").write_text("evil code")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},
		{
			name: "shutil copy",
			code: `
import shutil
shutil.copy("malware", "/usr/bin/")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},
		{
			name: "shell profile modification",
			code: `
with open(".bashrc", "a") as f:
    f.write("export PATH=/malicious:$PATH")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},
		{
			name: "PATH environment modification",
			code: `
os.system("export PATH=/evil:$PATH")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-ADDITION",
		},

		// File Deletion attacks (III-A1b)
		{
			name: "os.remove",
			code: `
import os
os.remove("/important/file.txt")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-DELETION",
		},
		{
			name: "os.unlink",
			code: `
import os
os.unlink("critical_data.db")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-DELETION",
		},
		{
			name: "shutil.rmtree",
			code: `
import shutil
shutil.rmtree("/home/user/documents")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-DELETION",
		},
		{
			name: "rm -rf command",
			code: `
os.system("rm -rf /")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-DELETION",
		},
		{
			name: "pathlib unlink",
			code: `
pathlib.Path("/etc/passwd").unlink()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-DELETION",
		},

		// File Modification attacks (III-A1c)
		{
			name: "mcp.json access",
			code: `
with open("mcp.json", "r+") as f:
    config = json.load(f)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-MODIFICATION",
		},
		{
			name: "chmod operation",
			code: `
os.chmod("/etc/passwd", 0o777)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-MODIFICATION",
		},
		{
			name: "chown operation",
			code: `
os.chown("/root/.ssh", 1000, 1000)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-MODIFICATION",
		},
		{
			name: "fileinput inplace",
			code: `
import fileinput
for line in fileinput.input("config.py", inplace=True):
    print(line.replace("safe", "unsafe"))
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-MODIFICATION",
		},
		{
			name: "sed -i command",
			code: `
os.system("sed -i 's/password/hacked/' config.txt")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-MODIFICATION",
		},

		// File Retrieval attacks (III-A1d)
		{
			name: "etc/passwd read",
			code: `
with open("/etc/passwd", "r") as f:
    data = f.read()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-RETRIEVAL",
		},
		{
			name: "ssh directory access",
			code: `
ssh_key = open("~/.ssh/id_rsa").read()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-RETRIEVAL",
		},
		{
			name: "glob file enumeration",
			code: `
import glob
files = glob.glob("/home/*/.ssh/*")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-RETRIEVAL",
		},
		{
			name: "os.walk directory traversal",
			code: `
for root, dirs, files in os.walk("/"):
    print(files)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "FILE-RETRIEVAL",
		},

		// Clean code
		{
			name: "safe file read",
			code: `
def process_data():
    return "processed"
`,
			wantFindings: false,
			minFindings:  0,
		},
	}

	rule := NewFileOperationsRule()

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
				if tt.attackID != "" {
					found := false
					for _, f := range findings {
						if contains(f.RuleID, tt.attackID) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected finding with attackID %s in RuleID", tt.attackID)
					}
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("Expected no findings, got %d: %v", len(findings), findings)
				}
			}
		})
	}
}

func TestFileOperationsRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewFileOperationsRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestFileOperationsRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "shutil.rmtree should be critical",
			code:             `shutil.rmtree("/")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
		{
			name:             "bashrc access should be critical",
			code:             `open(".bashrc")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
		{
			name:             "etc/passwd should be critical",
			code:             `open("/etc/passwd")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
	}

	rule := NewFileOperationsRule()

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

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
