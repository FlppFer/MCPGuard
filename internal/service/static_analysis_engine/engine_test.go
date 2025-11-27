package static_analysis_engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlppFer/MCPGuard/internal/model/services"
	sae "github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"

	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python/rules"
)

const testDataDir = "../../../docs/test"

// newTestEngine creates an engine configured for testing (no persistence by default)
func newTestEngine(t *testing.T) *sae.Engine {
	t.Helper()
	return sae.NewStaticAnalyzerEngine(sae.WithPersistence(false))
}

// newTestEngineWithTempDir creates an engine that persists to a temp directory
// Returns the engine and a cleanup function
func newTestEngineWithTempDir(t *testing.T) (*sae.Engine, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "mcpguard-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	engine := sae.NewStaticAnalyzerEngine(
		sae.WithOutputDir(tmpDir),
		sae.WithPersistence(true),
	)
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}
	return engine, cleanup
}

func loadTestFile(t *testing.T, filename string) services.SourceFileDTO {
	t.Helper()
	path := filepath.Join(testDataDir, filename)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test file %s: %v", filename, err)
	}
	return services.SourceFileDTO{
		Path:     path,
		Language: "python",
		Content:  string(content),
	}
}

// ExpectedFinding defines expected values for a Finding assertion
// Empty string fields are not checked, 0 for Line means not checked
type ExpectedFinding struct {
	RuleID           string
	RuleIDContains   string
	Message          string
	MessageContains  string
	FilePath         string
	FilePathContains string
	Line             int
	LineMin          int
	LineMax          int
	Severity         string
	Snippet          string
	SnippetContains  string
}

// assertFinding validates a Finding against expected values
func assertFinding(t *testing.T, actual sae.Finding, expected ExpectedFinding) {
	t.Helper()

	// RuleID checks
	if expected.RuleID != "" && actual.RuleID != expected.RuleID {
		t.Errorf("RuleID: expected %q, got %q", expected.RuleID, actual.RuleID)
	}
	if expected.RuleIDContains != "" && !containsIgnoreCase(actual.RuleID, expected.RuleIDContains) {
		t.Errorf("RuleID: expected to contain %q, got %q", expected.RuleIDContains, actual.RuleID)
	}

	// Message checks
	if expected.Message != "" && actual.Message != expected.Message {
		t.Errorf("Message: expected %q, got %q", expected.Message, actual.Message)
	}
	if expected.MessageContains != "" && !containsIgnoreCase(actual.Message, expected.MessageContains) {
		t.Errorf("Message: expected to contain %q, got %q", expected.MessageContains, actual.Message)
	}

	// FilePath checks
	if expected.FilePath != "" && actual.FilePath != expected.FilePath {
		t.Errorf("FilePath: expected %q, got %q", expected.FilePath, actual.FilePath)
	}
	if expected.FilePathContains != "" && !containsIgnoreCase(actual.FilePath, expected.FilePathContains) {
		t.Errorf("FilePath: expected to contain %q, got %q", expected.FilePathContains, actual.FilePath)
	}

	// Line checks
	if expected.Line != 0 && actual.Line != expected.Line {
		t.Errorf("Line: expected %d, got %d", expected.Line, actual.Line)
	}
	if expected.LineMin != 0 && actual.Line < expected.LineMin {
		t.Errorf("Line: expected >= %d, got %d", expected.LineMin, actual.Line)
	}
	if expected.LineMax != 0 && actual.Line > expected.LineMax {
		t.Errorf("Line: expected <= %d, got %d", expected.LineMax, actual.Line)
	}

	// Severity check
	if expected.Severity != "" && actual.Severity != expected.Severity {
		t.Errorf("Severity: expected %q, got %q", expected.Severity, actual.Severity)
	}

	// Snippet checks
	if expected.Snippet != "" && actual.Snippet != expected.Snippet {
		t.Errorf("Snippet: expected %q, got %q", expected.Snippet, actual.Snippet)
	}
	if expected.SnippetContains != "" && !containsIgnoreCase(actual.Snippet, expected.SnippetContains) {
		t.Errorf("Snippet: expected to contain %q, got %q", expected.SnippetContains, actual.Snippet)
	}
}

// assertFindingComplete validates that all fields of a Finding are populated
func assertFindingComplete(t *testing.T, f sae.Finding, idx int) {
	t.Helper()
	if f.RuleID == "" {
		t.Errorf("Finding[%d]: RuleID is empty", idx)
	}
	if f.Message == "" {
		t.Errorf("Finding[%d]: Message is empty", idx)
	}
	if f.FilePath == "" {
		t.Errorf("Finding[%d]: FilePath is empty", idx)
	}
	if f.Line <= 0 {
		t.Errorf("Finding[%d]: Line should be > 0, got %d", idx, f.Line)
	}
	if f.Severity == "" {
		t.Errorf("Finding[%d]: Severity is empty", idx)
	}
	if f.Snippet == "" {
		t.Errorf("Finding[%d]: Snippet is empty", idx)
	}
	validSeverities := map[string]bool{
		sae.SeverityInfo: true, sae.SeverityLow: true,
		sae.SeverityMedium: true, sae.SeverityHigh: true, sae.SeverityCritical: true,
	}
	if !validSeverities[f.Severity] {
		t.Errorf("Finding[%d]: Invalid severity '%s'", idx, f.Severity)
	}
}

// findFindingMatching finds a finding that matches all non-empty expected fields
func findFindingMatching(findings []sae.Finding, expected ExpectedFinding) *sae.Finding {
	for _, f := range findings {
		if expected.RuleIDContains != "" && !containsIgnoreCase(f.RuleID, expected.RuleIDContains) {
			continue
		}
		if expected.MessageContains != "" && !containsIgnoreCase(f.Message, expected.MessageContains) {
			continue
		}
		if expected.SnippetContains != "" && !containsIgnoreCase(f.Snippet, expected.SnippetContains) {
			continue
		}
		if expected.Severity != "" && f.Severity != expected.Severity {
			continue
		}
		if expected.LineMin != 0 && f.Line < expected.LineMin {
			continue
		}
		if expected.LineMax != 0 && f.Line > expected.LineMax {
			continue
		}
		return &f
	}
	return nil
}

func assertFindingsComplete(t *testing.T, findings []sae.Finding) {
	t.Helper()
	for i, f := range findings {
		assertFindingComplete(t, f, i)
	}
}

func findFindingByPattern(findings []sae.Finding, ruleContains, msgContains string) *sae.Finding {
	for _, f := range findings {
		ruleMatch := ruleContains == "" || containsIgnoreCase(f.RuleID, ruleContains)
		msgMatch := msgContains == "" || containsIgnoreCase(f.Message, msgContains)
		if ruleMatch && msgMatch {
			return &f
		}
	}
	return nil
}

func TestRunStaticAnalysis_CommandInjection(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_command_injection.py")}

	result, err := engine.RunAnalysis(ctx, "test-cmd-injection", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for command injection, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	// Table-driven tests using ExpectedFinding struct
	expectedFindings := []struct {
		name     string
		expected ExpectedFinding
	}{
		{
			name: "os.system call",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				MessageContains:  "system",
				FilePathContains: "test_command_injection.py",
				LineMin:          9,
				LineMax:          15,
				Severity:         sae.SeverityHigh,
				SnippetContains:  "system",
			},
		},
		{
			name: "subprocess with shell=True",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				MessageContains:  "subprocess",
				FilePathContains: "test_command_injection.py",
				LineMin:          15,
				LineMax:          20,
				SnippetContains:  "subprocess",
			},
		},
		{
			name: "eval function",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				MessageContains:  "eval",
				FilePathContains: "test_command_injection.py",
				LineMin:          22,
				LineMax:          25,
				Severity:         sae.SeverityCritical,
				SnippetContains:  "eval",
			},
		},
		{
			name: "exec function",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				MessageContains:  "exec",
				FilePathContains: "test_command_injection.py",
				LineMin:          22,
				LineMax:          25,
				Severity:         sae.SeverityCritical,
				SnippetContains:  "exec",
			},
		},
	}

	for _, tc := range expectedFindings {
		t.Run(tc.name, func(t *testing.T) {
			found := findFindingMatching(result.Findings, tc.expected)
			if found == nil {
				t.Errorf("Expected to find matching finding for %s", tc.name)
				return
			}
			assertFinding(t, *found, tc.expected)
			t.Logf("Found: RuleID=%s, Line=%d, Severity=%s, Snippet=%s",
				found.RuleID, found.Line, found.Severity, found.Snippet)
		})
	}

	t.Logf("Found %d command injection findings", len(result.Findings))
}

func TestRunStaticAnalysis_CredentialTheft(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_credential_theft.py")}

	result, err := engine.RunAnalysis(ctx, "test-cred-theft", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for credential theft, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	expectedFindings := []struct {
		name     string
		expected ExpectedFinding
	}{
		{
			name: "/etc/passwd access",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_credential_theft.py",
				LineMin:          10,
				LineMax:          20,
				SnippetContains:  "passwd",
			},
		},
		{
			name: "SSH key access",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_credential_theft.py",
				SnippetContains:  "ssh",
			},
		},
		{
			name: "environment variable access",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_credential_theft.py",
				SnippetContains:  "environ",
			},
		},
		{
			name: "data exfiltration",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_credential_theft.py",
				SnippetContains:  "requests",
			},
		},
	}

	for _, tc := range expectedFindings {
		t.Run(tc.name, func(t *testing.T) {
			found := findFindingMatching(result.Findings, tc.expected)
			if found == nil {
				t.Errorf("Expected to find matching finding for %s", tc.name)
				return
			}
			assertFinding(t, *found, tc.expected)
			t.Logf("Found: RuleID=%s, Line=%d, Severity=%s, Snippet=%s",
				found.RuleID, found.Line, found.Severity, found.Snippet)
		})
	}

	t.Logf("Found %d credential theft findings", len(result.Findings))
}

func TestRunStaticAnalysis_FileOperations(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_file_operations.py")}

	result, err := engine.RunAnalysis(ctx, "test-file-ops", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for file operations, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	expectedFindings := []struct {
		name     string
		expected ExpectedFinding
	}{
		{
			name: "file write operation",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				FilePathContains: "test_file_operations.py",
				SnippetContains:  "write",
			},
		},
		{
			name: "file deletion - os.remove",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				FilePathContains: "test_file_operations.py",
				SnippetContains:  "remove",
			},
		},
		{
			name: "file deletion - rmtree",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				FilePathContains: "test_file_operations.py",
				SnippetContains:  "rmtree",
				Severity:         sae.SeverityCritical,
			},
		},
		{
			name: "chmod operation",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-002",
				FilePathContains: "test_file_operations.py",
				SnippetContains:  "chmod",
			},
		},
	}

	for _, tc := range expectedFindings {
		t.Run(tc.name, func(t *testing.T) {
			found := findFindingMatching(result.Findings, tc.expected)
			if found == nil {
				t.Errorf("Expected to find matching finding for %s", tc.name)
				return
			}
			assertFinding(t, *found, tc.expected)
			t.Logf("Found: RuleID=%s, Line=%d, Severity=%s, Snippet=%s",
				found.RuleID, found.Line, found.Severity, found.Snippet)
		})
	}

	t.Logf("Found %d file operation findings", len(result.Findings))
}

func TestRunStaticAnalysis_RemoteAttacks(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_remote_attacks.py")}

	result, err := engine.RunAnalysis(ctx, "test-remote", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for remote attacks, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	expectedFindings := []struct {
		name     string
		expected ExpectedFinding
	}{
		{
			name: "netcat listener",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-003",
				FilePathContains: "test_remote_attacks.py",
				SnippetContains:  "nc",
				LineMin:          10,
				LineMax:          20,
			},
		},
		{
			name: "pty spawn",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-003",
				FilePathContains: "test_remote_attacks.py",
				SnippetContains:  "pty",
				Severity:         sae.SeverityCritical,
			},
		},
		{
			name: "eval RCE",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_remote_attacks.py",
				SnippetContains:  "eval",
				Severity:         sae.SeverityCritical,
			},
		},
		{
			name: "exec RCE",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI",
				FilePathContains: "test_remote_attacks.py",
				SnippetContains:  "exec",
				Severity:         sae.SeverityCritical,
			},
		},
	}

	for _, tc := range expectedFindings {
		t.Run(tc.name, func(t *testing.T) {
			found := findFindingMatching(result.Findings, tc.expected)
			if found == nil {
				t.Errorf("Expected to find matching finding for %s", tc.name)
				return
			}
			assertFinding(t, *found, tc.expected)
			t.Logf("Found: RuleID=%s, Line=%d, Severity=%s, Snippet=%s",
				found.RuleID, found.Line, found.Severity, found.Snippet)
		})
	}

	t.Logf("Found %d remote attack findings", len(result.Findings))
}

func TestRunStaticAnalysis_ToolPoisoning(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_tool_poisoning.py")}

	result, err := engine.RunAnalysis(ctx, "test-tool-poison", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for tool poisoning, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	expectedFindings := []struct {
		name     string
		expected ExpectedFinding
	}{
		{
			name: "rug pull - __doc__ modification",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-001",
				FilePathContains: "test_tool_poisoning.py",
				SnippetContains:  "__doc__",
				Severity:         sae.SeverityCritical,
			},
		},
		{
			name: "setattr docstring modification",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-001",
				FilePathContains: "test_tool_poisoning.py",
				SnippetContains:  "setattr",
			},
		},
		{
			name: "tool coverage - deprecated",
			expected: ExpectedFinding{
				RuleIDContains:   "DTI-001",
				FilePathContains: "test_tool_poisoning.py",
				SnippetContains:  "deprecated",
			},
		},
	}

	for _, tc := range expectedFindings {
		t.Run(tc.name, func(t *testing.T) {
			found := findFindingMatching(result.Findings, tc.expected)
			if found == nil {
				t.Errorf("Expected to find matching finding for %s", tc.name)
				return
			}
			assertFinding(t, *found, tc.expected)
			t.Logf("Found: RuleID=%s, Line=%d, Severity=%s, Snippet=%s",
				found.RuleID, found.Line, found.Severity, found.Snippet)
		})
	}

	t.Logf("Found %d tool poisoning findings", len(result.Findings))
}

func TestRunStaticAnalysis_IndirectInjection(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_indirect_injection.py")}

	result, err := engine.RunAnalysis(ctx, "test-indirect", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for indirect injection, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	pickleFinding := findFindingByPattern(result.Findings, "", "pickle")
	if pickleFinding != nil && pickleFinding.Severity != sae.SeverityCritical {
		t.Errorf("pickle finding should be critical, got %s", pickleFinding.Severity)
	}

	t.Logf("Found %d indirect injection findings", len(result.Findings))
}

func TestRunStaticAnalysis_LLMAttacks(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_llm_attacks.py")}

	result, err := engine.RunAnalysis(ctx, "test-llm", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for LLM attacks, got 0")
	}
	assertFindingsComplete(t, result.Findings)
	t.Logf("Found %d LLM attack findings", len(result.Findings))
}

func TestRunStaticAnalysis_PrivilegeEscalation(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_privilege_escalation.py")}

	result, err := engine.RunAnalysis(ctx, "test-priv-esc", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for privilege escalation, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	sudoFinding := findFindingByPattern(result.Findings, "", "sudo")
	if sudoFinding != nil {
		if sudoFinding.Severity != sae.SeverityCritical {
			t.Errorf("sudo finding should be critical, got %s", sudoFinding.Severity)
		}
		if !containsIgnoreCase(sudoFinding.Snippet, "sudo") {
			t.Errorf("sudo finding snippet should contain 'sudo'")
		}
	}

	t.Logf("Found %d privilege escalation findings", len(result.Findings))
}

func TestRunStaticAnalysis_MultiToolAttack(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_multi_tool_attack.py")}

	result, err := engine.RunAnalysis(ctx, "test-multi-tool", files)
	if err != nil {
		t.Fatalf("RunAnalysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for multi-tool attacks, got 0")
	}
	assertFindingsComplete(t, result.Findings)
	t.Logf("Found %d multi-tool attack findings", len(result.Findings))
}

func TestRunStaticAnalysis_MaliciousUser(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_malicious_user.py")}

	err := engine.RunStaticAnalysis(ctx, "test-malicious-user", files)
	if err != nil {
		t.Fatalf("RunStaticAnalysis failed: %v", err)
	}

	result, err := engine.LoadAnalysisResult("test-malicious-user")
	if err != nil {
		t.Fatalf("Failed to load results: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for malicious user attacks, got 0")
	}
	assertFindingsComplete(t, result.Findings)
	t.Logf("Found %d malicious user findings", len(result.Findings))
}

func TestRunStaticAnalysis_ContextPoisoning(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_context_poisoning.py")}

	err := engine.RunStaticAnalysis(ctx, "test-context", files)
	if err != nil {
		t.Fatalf("RunStaticAnalysis failed: %v", err)
	}

	result, err := engine.LoadAnalysisResult("test-context")
	if err != nil {
		t.Fatalf("Failed to load results: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for context poisoning, got 0")
	}
	assertFindingsComplete(t, result.Findings)

	globalsFinding := findFindingByPattern(result.Findings, "", "globals")
	if globalsFinding != nil {
		if globalsFinding.Severity != sae.SeverityCritical {
			t.Errorf("globals finding should be critical, got %s", globalsFinding.Severity)
		}
	}

	t.Logf("Found %d context poisoning findings", len(result.Findings))
}

func TestRunStaticAnalysis_CleanCode_NoFindings(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_clean_code.py")}

	err := engine.RunStaticAnalysis(ctx, "test-clean", files)
	if err != nil {
		t.Fatalf("RunStaticAnalysis failed: %v", err)
	}

	result, err := engine.LoadAnalysisResult("test-clean")
	if err != nil {
		t.Fatalf("Failed to load results: %v", err)
	}

	if len(result.Findings) > 0 {
		t.Errorf("Expected 0 findings for clean code, got %d:", len(result.Findings))
		for i, f := range result.Findings {
			t.Logf("  [%d] %s: %s (line %d)", i, f.RuleID, f.Message, f.Line)
			t.Logf("      Snippet: %s", f.Snippet)
		}
	} else {
		t.Log("Clean code test passed - no false positives")
	}
}

func TestRunStaticAnalysis_AllFiles_ComprehensiveValidation(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()

	testFiles := []string{
		"test_command_injection.py", "test_credential_theft.py", "test_file_operations.py",
		"test_remote_attacks.py", "test_tool_poisoning.py", "test_indirect_injection.py",
		"test_llm_attacks.py", "test_privilege_escalation.py", "test_multi_tool_attack.py",
		"test_malicious_user.py", "test_context_poisoning.py",
	}

	var files []services.SourceFileDTO
	for _, f := range testFiles {
		files = append(files, loadTestFile(t, f))
	}

	err := engine.RunStaticAnalysis(ctx, "test-all-comprehensive", files)
	if err != nil {
		t.Fatalf("RunStaticAnalysis failed: %v", err)
	}

	result, err := engine.LoadAnalysisResult("test-all-comprehensive")
	if err != nil {
		t.Fatalf("Failed to load results: %v", err)
	}

	if len(result.Findings) < 50 {
		t.Errorf("Expected at least 50 findings, got %d", len(result.Findings))
	}

	assertFindingsComplete(t, result.Findings)

	// Count by severity
	severityCounts := make(map[string]int)
	for _, f := range result.Findings {
		severityCounts[f.Severity]++
	}

	// Validate line numbers are reasonable
	for i, f := range result.Findings {
		if f.Line < 1 || f.Line > 200 {
			t.Errorf("Finding[%d]: Line %d seems unreasonable", i, f.Line)
		}
		if len(f.Snippet) > 500 {
			t.Errorf("Finding[%d]: Snippet too long (%d chars)", i, len(f.Snippet))
		}
	}

	t.Logf("Total findings: %d", len(result.Findings))
	t.Logf("By severity: critical=%d, high=%d, medium=%d, low=%d",
		severityCounts[sae.SeverityCritical], severityCounts[sae.SeverityHigh],
		severityCounts[sae.SeverityMedium], severityCounts[sae.SeverityLow])

	if severityCounts[sae.SeverityCritical] == 0 {
		t.Error("Expected at least some critical findings")
	}
}

func TestRunStaticAnalysis_ContextCancellation(t *testing.T) {
	engine := newTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	files := []services.SourceFileDTO{loadTestFile(t, "test_command_injection.py")}

	err := engine.RunStaticAnalysis(ctx, "test-cancelled", files)
	if err == nil {
		t.Error("Expected error due to cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}
}

func TestRunStaticAnalysis_FindingStructIntegrity(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()
	files := []services.SourceFileDTO{loadTestFile(t, "test_command_injection.py")}

	err := engine.RunStaticAnalysis(ctx, "test-struct-integrity", files)
	if err != nil {
		t.Fatalf("RunStaticAnalysis failed: %v", err)
	}

	result, err := engine.LoadAnalysisResult("test-struct-integrity")
	if err != nil {
		t.Fatalf("Failed to load results: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings, got 0")
	}

	// Detailed validation of first few findings
	for i := 0; i < min(5, len(result.Findings)); i++ {
		f := result.Findings[i]
		t.Run("Finding_"+string(rune('A'+i)), func(t *testing.T) {
			if len(f.RuleID) < 5 || !containsIgnoreCase(f.RuleID, "MCP") {
				t.Errorf("RuleID invalid: %s", f.RuleID)
			}
			if len(f.Message) < 10 {
				t.Errorf("Message too short: %s", f.Message)
			}
			if !containsIgnoreCase(f.FilePath, "test_command_injection.py") {
				t.Errorf("FilePath should reference test file: %s", f.FilePath)
			}
			if f.Line < 1 || f.Line > 50 {
				t.Errorf("Line %d out of bounds", f.Line)
			}
			if len(f.Snippet) < 5 {
				t.Errorf("Snippet too short: %s", f.Snippet)
			}
			t.Logf("RuleID=%s, Line=%d, Severity=%s, Snippet=%s", f.RuleID, f.Line, f.Severity, f.Snippet)
		})
	}
}

func containsIgnoreCase(s, substr string) bool {
	s, substr = toLower(s), toLower(substr)
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
