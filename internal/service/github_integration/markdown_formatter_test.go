package github_integration

import (
	"strings"
	"testing"

	"github.com/FlppFer/MCPGuard/internal/service/model"
)

func TestFormatFindingsMarkdown_NoFindings(t *testing.T) {
	result := &model.AnalysisResult{
		AnalysisID: "test-123",
		Files:      5,
		Findings:   nil,
	}

	md := FormatFindingsMarkdown(result)

	if !strings.Contains(md, "No security issues detected") {
		t.Error("expected clean message for zero findings")
	}
	if !strings.Contains(md, "`test-123`") {
		t.Error("expected analysis ID in output")
	}
	if !strings.Contains(md, "**Total findings:** 0") {
		t.Error("expected total findings count of 0")
	}
}

func TestFormatFindingsMarkdown_WithFindings(t *testing.T) {
	result := &model.AnalysisResult{
		AnalysisID: "test-456",
		Files:      10,
		Findings: []model.Finding{
			{RuleID: "R001", Message: "Unsafe call", FilePath: "main.py", Line: 10, Severity: model.SeverityHigh},
			{RuleID: "R002", Message: "Hardcoded secret", FilePath: "config.py", Line: 3, Severity: model.SeverityCritical},
			{RuleID: "R003", Message: "Weak hash", FilePath: "utils.py", Line: 42, Severity: model.SeverityMedium},
			{RuleID: "R004", Message: "Debug left on", FilePath: "app.py", Line: 7, Severity: model.SeverityLow},
			{RuleID: "R005", Message: "Missing docstring", FilePath: "lib.py", Line: 1, Severity: model.SeverityInfo},
		},
	}

	md := FormatFindingsMarkdown(result)

	if !strings.Contains(md, "**Total findings:** 5") {
		t.Error("expected total findings count of 5")
	}
	if !strings.Contains(md, "### Severity Breakdown") {
		t.Error("expected severity breakdown section")
	}
	if !strings.Contains(md, "**CRITICAL:** 1") {
		t.Error("expected critical count")
	}
	if !strings.Contains(md, "**HIGH:** 1") {
		t.Error("expected high count")
	}
	if !strings.Contains(md, "| Severity | Rule | File | Message |") {
		t.Error("expected findings table header")
	}
	if !strings.Contains(md, "`main.py:10`") {
		t.Error("expected file:line format in table")
	}
	if !strings.Contains(md, "`R001`") {
		t.Error("expected rule ID in table")
	}
}

func TestFormatFindingsMarkdown_MoreThan20Findings(t *testing.T) {
	findings := make([]model.Finding, 25)
	for i := range findings {
		findings[i] = model.Finding{
			RuleID:   "R999",
			Message:  "Some issue",
			FilePath: "file.py",
			Line:     i + 1,
			Severity: model.SeverityMedium,
		}
	}

	result := &model.AnalysisResult{
		AnalysisID: "test-789",
		Files:      1,
		Findings:   findings,
	}

	md := FormatFindingsMarkdown(result)

	if !strings.Contains(md, "**Total findings:** 25") {
		t.Error("expected total findings count of 25")
	}
	// All 25 findings should be shown (limit is 100 now)
	rows := strings.Count(md, "| medium |")
	if rows != 25 {
		t.Errorf("expected 25 table rows, got %d", rows)
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 80) != "short" {
		t.Error("short string should not be truncated")
	}
	long := strings.Repeat("a", 100)
	result := truncate(long, 80)
	if len(result) != 80 {
		t.Errorf("expected length 80, got %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("truncated string should end with ...")
	}
}
