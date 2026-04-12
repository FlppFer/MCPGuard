package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSFileOperationsRule_ID(t *testing.T) {
	rule := NewJSFileOperationsRule()
	if rule.ID() != "MCP-JS-FS-001" {
		t.Errorf("ID() = %v, want MCP-JS-FS-001", rule.ID())
	}
}

func TestJSFileOperationsRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSFileOperationsRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSFileOperationsRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "fs.readFileSync",
			code:         `fs.readFileSync('/etc/passwd');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.writeFileSync",
			code:         `fs.writeFileSync('/tmp/out.txt', data);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.unlinkSync",
			code:         `fs.unlinkSync('/tmp/secret.txt');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.rmdirSync",
			code:         `fs.rmdirSync('/tmp/dir');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.chmodSync",
			code:         `fs.chmodSync('/tmp/file', 0o777);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.chownSync",
			code:         `fs.chownSync('/tmp/file', 0, 0);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.promises.readFile",
			code:         `await fs.promises.readFile('/etc/shadow');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.promises.writeFile",
			code:         `await fs.promises.writeFile('/tmp/data.txt', 'payload');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fs.promises.unlink",
			code:         `await fs.promises.unlink('/tmp/remove.txt');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "path traversal in string",
			code:         `const path = '../../../etc/passwd';`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; const name = "safe";`,
			wantFindings: false,
		},
	}

	rule := NewJSFileOperationsRule()

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

func TestJSFileOperationsRule_SensitivePathSeverity(t *testing.T) {
	rule := NewJSFileOperationsRule()

	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`fs.readFileSync('/etc/passwd');`))
	if err != nil {
		t.Fatal(err)
	}

	findings, _ := rule.Evaluate(ast)
	hasHighSeverity := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			hasHighSeverity = true
			break
		}
	}
	if !hasHighSeverity {
		t.Error("Expected at least one HIGH severity finding for /etc/passwd access")
	}
}

func TestJSFileOperationsRule_NonJSAST(t *testing.T) {
	rule := NewJSFileOperationsRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error on non-JS AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil for non-JS AST, got %v", findings)
	}
}
