package github_integration

import (
	"fmt"
	"strings"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
)

// FormatAgenticFindingsMarkdown formats agentic analysis results as a GitHub-compatible Markdown comment.
func FormatAgenticFindingsMarkdown(result *httpmodel.AgenticAnalysisResultDTO) string {
	var sb strings.Builder

	sb.WriteString("## MCPGuard AI Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Analysis ID:** `%s`\n", result.AnalysisID))
	if result.ModelUsed != "" {
		sb.WriteString(fmt.Sprintf("**Model:** `%s`\n", result.ModelUsed))
	}
	sb.WriteString(fmt.Sprintf("**Total findings:** %d\n\n", len(result.Findings)))

	if result.Summary != "" {
		sb.WriteString("### Summary\n\n")
		sb.WriteString(result.Summary + "\n\n")
	}

	if len(result.Findings) == 0 {
		sb.WriteString("No AI-detected security issues.\n")
		return sb.String()
	}

	sb.WriteString("### Findings\n\n")
	sb.WriteString("| Severity | Confidence | Category | File | Lines | Description |\n")
	sb.WriteString("|----------|------------|----------|------|-------|-------------|\n")

	for _, f := range result.Findings {
		lines := fmt.Sprintf("%d", f.StartLine)
		if f.EndLine > f.StartLine {
			lines = fmt.Sprintf("%d–%d", f.StartLine, f.EndLine)
		}
		row := fmt.Sprintf("| %s | %.0f%% | %s | `%s` | %s | %s |\n",
			f.Severity,
			float64(f.Confidence)*100,
			f.Category,
			f.FilePath,
			lines,
			truncate(f.Description, 100),
		)
		if sb.Len()+len(row) > maxCommentChars {
			sb.WriteString("\n_...truncated. See full results via the API._\n")
			break
		}
		sb.WriteString(row)
	}

	return sb.String()
}
