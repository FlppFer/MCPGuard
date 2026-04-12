package github_integration

import (
	"fmt"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
)

const maxFindingsInComment = 20

// FormatFindingsMarkdown formats analysis results as a GitHub-compatible Markdown comment.
func FormatFindingsMarkdown(result *model.AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("## MCPGuard Security Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Analysis ID:** `%s`\n", result.AnalysisID))
	sb.WriteString(fmt.Sprintf("**Files analyzed:** %d\n", result.Files))
	sb.WriteString(fmt.Sprintf("**Total findings:** %d\n\n", len(result.Findings)))

	if len(result.Findings) == 0 {
		sb.WriteString("No security issues detected.\n")
		return sb.String()
	}

	// Severity breakdown
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	sb.WriteString("### Severity Breakdown\n\n")
	for _, sev := range []string{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	} {
		if c, ok := counts[sev]; ok {
			sb.WriteString(fmt.Sprintf("- **%s:** %d\n", strings.ToUpper(sev), c))
		}
	}

	// Findings table (top N)
	sb.WriteString("\n### Findings\n\n")
	sb.WriteString("| Severity | Rule | File | Line | Message |\n")
	sb.WriteString("|----------|------|------|------|---------|\n")
	limit := maxFindingsInComment
	if len(result.Findings) < limit {
		limit = len(result.Findings)
	}
	for _, f := range result.Findings[:limit] {
		sb.WriteString(fmt.Sprintf("| %s | `%s` | `%s` | %d | %s |\n",
			f.Severity, f.RuleID, f.FilePath, f.Line, truncate(f.Message, 80)))
	}
	if len(result.Findings) > maxFindingsInComment {
		sb.WriteString(fmt.Sprintf("\n_...and %d more findings. See full results via the API._\n",
			len(result.Findings)-maxFindingsInComment))
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
