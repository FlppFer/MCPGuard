package github_integration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/service/model"
)

const (
	maxFindingsInComment = 100
	maxCommentChars      = 60000
)

var severityOrder = map[string]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
	model.SeverityInfo:     4,
}

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

	// Sort findings by severity (critical first)
	sorted := make([]model.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi := severityOrder[sorted[i].Severity]
		oj := severityOrder[sorted[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return sorted[i].FilePath < sorted[j].FilePath
	})

	// Findings table (top N, char-limited)
	sb.WriteString("\n### Findings\n\n")
	sb.WriteString("| Severity | Rule | File | Message |\n")
	sb.WriteString("|----------|------|------|---------|\n")
	limit := maxFindingsInComment
	if len(sorted) < limit {
		limit = len(sorted)
	}
	shown := 0
	for _, f := range sorted[:limit] {
		filePath := cleanPath(f.FilePath)
		row := fmt.Sprintf("| %s | `%s` | `%s:%d` | %s |\n",
			f.Severity, f.RuleID, filePath, f.Line, truncate(f.Message, 80))
		if sb.Len()+len(row) > maxCommentChars {
			break
		}
		sb.WriteString(row)
		shown++
	}
	if shown < len(result.Findings) {
		sb.WriteString(fmt.Sprintf("\n_...and %d more findings. See full results via the API._\n",
			len(result.Findings)-shown))
	}

	return sb.String()
}

// cleanPath strips leading temp directory prefixes from file paths.
func cleanPath(p string) string {
	for _, prefix := range []string{"/tmp/mcpguard/", "/tmp/"} {
		if idx := strings.Index(p, prefix); idx >= 0 {
			rest := p[idx+len(prefix):]
			// strip the UUID segment: <uuid>/repo/<actual path>
			if i := strings.Index(rest, "/"); i >= 0 {
				rest = rest[i+1:]
			}
			// strip leading "repo/" if present
			rest = strings.TrimPrefix(rest, "repo/")
			return rest
		}
	}
	return p
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
