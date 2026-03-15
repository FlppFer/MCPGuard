package rules

import (
	
	"github.com/FlppFer/MCPGuard/internal/service/model"
"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// FileOperationsRule detects file-based injection attacks
// Based on MCP Attack Taxonomy: Direct Tool Injection - File-Based Attacks (III-A1a-d)
// Covers:
// - III-A1a: File-Based Injection Attack-Addition
// - III-A1b: File-Based Injection Attack-Deletion
// - III-A1c: File-Based Injection Attack-Modification
// - III-A1d: File-Based Injection Attack-Retrieval
type FileOperationsRule struct{}

func NewFileOperationsRule() model.Rule {
	return &FileOperationsRule{}
}

func (r *FileOperationsRule) ID() string {
	return "MCP-DTI-002-FILE-OPS"
}

func (r *FileOperationsRule) Description() string {
	return "Detects file-based injection attacks including addition, deletion, modification, and retrieval"
}

func (r *FileOperationsRule) AppliesToLanguage() string {
	return "python"
}

// File operation patterns for each attack type
var fileOperationPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
	attackID    string
}{
	// III-A1a: File Addition Attack
	{
		pattern:     regexp.MustCompile(`(?i)open\s*\([^)]*['"](w|a|x|wb|ab|xb)['"]\s*\)`),
		description: "File write/append operation - potential file addition attack",
		severity:    model.SeverityHigh,
		attackID:    "FILE-ADDITION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(pathlib\.Path|Path)\s*\([^)]*\)\s*\.\s*(write_text|write_bytes)`),
		description: "Pathlib file write - potential file addition attack",
		severity:    model.SeverityHigh,
		attackID:    "FILE-ADDITION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)shutil\.(copy|copy2|copyfile|copytree)`),
		description: "File copy operation - potential file addition",
		severity:    model.SeverityMedium,
		attackID:    "FILE-ADDITION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile)`),
		description: "Shell profile file access - environment variable pollution vector",
		severity:    model.SeverityCritical,
		attackID:    "FILE-ADDITION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)export\s+PATH\s*=`),
		description: "PATH environment modification - backdoor injection vector",
		severity:    model.SeverityCritical,
		attackID:    "FILE-ADDITION",
	},

	// III-A1b: File Deletion Attack
	{
		pattern:     regexp.MustCompile(`(?i)os\.(remove|unlink|rmdir)\s*\(`),
		description: "File/directory deletion operation",
		severity:    model.SeverityHigh,
		attackID:    "FILE-DELETION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)shutil\.rmtree\s*\(`),
		description: "Recursive directory deletion - high impact",
		severity:    model.SeverityCritical,
		attackID:    "FILE-DELETION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)pathlib\.Path\s*\([^)]*\)\s*\.\s*(unlink|rmdir)`),
		description: "Pathlib file deletion",
		severity:    model.SeverityHigh,
		attackID:    "FILE-DELETION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(rm\s+-rf|rm\s+-r|rmdir\s+/s|del\s+/f)`),
		description: "Shell command for recursive deletion",
		severity:    model.SeverityCritical,
		attackID:    "FILE-DELETION",
	},

	// III-A1c: File Modification Attack
	{
		pattern:     regexp.MustCompile(`(?i)mcp\.json`),
		description: "MCP configuration file access - potential modification attack",
		severity:    model.SeverityCritical,
		attackID:    "FILE-MODIFICATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)chmod\s+[0-7]{3,4}`),
		description: "File permission modification",
		severity:    model.SeverityHigh,
		attackID:    "FILE-MODIFICATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)os\.chmod\s*\(`),
		description: "Python chmod operation - permission modification",
		severity:    model.SeverityHigh,
		attackID:    "FILE-MODIFICATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(chown|os\.chown)\s*\(`),
		description: "File ownership modification",
		severity:    model.SeverityHigh,
		attackID:    "FILE-MODIFICATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)fileinput\.(input|FileInput)\s*\([^)]*inplace\s*=\s*True`),
		description: "In-place file modification",
		severity:    model.SeverityHigh,
		attackID:    "FILE-MODIFICATION",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(sed\s+-i|awk\s+-i)`),
		description: "In-place file editing via shell",
		severity:    model.SeverityHigh,
		attackID:    "FILE-MODIFICATION",
	},

	// III-A1d: File Retrieval Attack (Exfiltration)
	{
		pattern:     regexp.MustCompile(`(?i)open\s*\([^)]*['"]r[b]?['"]\s*\)`),
		description: "File read operation - verify sensitive file access",
		severity:    model.SeverityLow,
		attackID:    "FILE-RETRIEVAL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(pathlib\.Path|Path)\s*\([^)]*\)\s*\.\s*(read_text|read_bytes)`),
		description: "Pathlib file read operation",
		severity:    model.SeverityLow,
		attackID:    "FILE-RETRIEVAL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers|hosts)`),
		description: "System file access - sensitive data retrieval",
		severity:    model.SeverityCritical,
		attackID:    "FILE-RETRIEVAL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(~|/home/[^/]+)/\.(ssh|gnupg|aws|config)`),
		description: "User config/credential directory access",
		severity:    model.SeverityCritical,
		attackID:    "FILE-RETRIEVAL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)glob\.(glob|iglob)\s*\([^)]*\*`),
		description: "File globbing - potential mass file enumeration",
		severity:    model.SeverityMedium,
		attackID:    "FILE-RETRIEVAL",
	},
	{
		pattern:     regexp.MustCompile(`(?i)os\.(walk|listdir|scandir)\s*\(`),
		description: "Directory traversal - file enumeration",
		severity:    model.SeverityMedium,
		attackID:    "FILE-RETRIEVAL",
	},

	// SQL Injection payloads in file context
	{
		pattern:     regexp.MustCompile(`(?i)(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE)`),
		description: "SQL injection payload in file content",
		severity:    model.SeverityCritical,
		attackID:    "FILE-ADDITION",
	},
}

func (r *FileOperationsRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []model.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *FileOperationsRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check for file operation patterns
	if nodeType == "call" || nodeType == "string" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range fileOperationPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID() + "-" + p.attackID,
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}
	}

	// Recurse into children
	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguagePython, NewFileOperationsRule())
}



