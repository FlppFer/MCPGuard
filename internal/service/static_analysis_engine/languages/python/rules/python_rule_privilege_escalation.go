package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis_engine/languages/python"
	sitter "github.com/smacker/go-tree-sitter"
)

// PrivilegeEscalationRule detects privilege escalation and sandbox escape attempts
// Based on MCP Attack Taxonomy: Malicious User Attack (III-C2, III-C7)
type PrivilegeEscalationRule struct{}

func NewPrivilegeEscalationRule() static_analysis_engine.Rule {
	return &PrivilegeEscalationRule{}
}

func (r *PrivilegeEscalationRule) ID() string {
	return "MCP-MUA-001"
}

func (r *PrivilegeEscalationRule) Description() string {
	return "Detects privilege escalation and sandbox escape attempts"
}

func (r *PrivilegeEscalationRule) AppliesToLanguage() string {
	return "python"
}

// Privilege escalation patterns
var privilegeEscalationPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	// Direct privilege escalation
	{
		pattern:     regexp.MustCompile(`(?i)(sudo|su\s+-|runas|doas)\s+`),
		description: "Privilege elevation command detected",
		severity:    static_analysis_engine.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)setuid|setgid|seteuid|setegid`),
		description: "UID/GID manipulation detected",
		severity:    static_analysis_engine.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)os\.setuid|os\.setgid|os\.seteuid|os\.setegid`),
		description: "Python UID/GID manipulation",
		severity:    static_analysis_engine.SeverityCritical,
	},

	// Sandbox escape patterns
	{
		pattern:     regexp.MustCompile(`(?i)ctypes\.CDLL|ctypes\.cdll`),
		description: "Native library loading - potential sandbox escape",
		severity:    static_analysis_engine.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)cffi\.FFI`),
		description: "CFFI usage - potential sandbox escape via native code",
		severity:    static_analysis_engine.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)/proc/(self|[0-9]+)/(mem|maps|fd)`),
		description: "Process memory access - potential sandbox escape",
		severity:    static_analysis_engine.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)ptrace|process_vm_readv|process_vm_writev`),
		description: "Process tracing/memory access - sandbox escape vector",
		severity:    static_analysis_engine.SeverityCritical,
	},

	// Container/virtualization escape
	{
		pattern:     regexp.MustCompile(`(?i)/var/run/docker\.sock`),
		description: "Docker socket access - container escape vector",
		severity:    static_analysis_engine.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.dockerenv|/proc/1/cgroup`),
		description: "Container detection - may be used for escape attempts",
		severity:    static_analysis_engine.SeverityMedium,
	},
	{
		pattern:     regexp.MustCompile(`(?i)nsenter|unshare|setns`),
		description: "Namespace manipulation - container escape vector",
		severity:    static_analysis_engine.SeverityCritical,
	},

	// File system escape
	{
		pattern:     regexp.MustCompile(`(?i)\.\./\.\./|\.\.\\\.\.\\`),
		description: "Path traversal pattern - potential sandbox escape",
		severity:    static_analysis_engine.SeverityHigh,
	},
	{
		pattern:     regexp.MustCompile(`(?i)os\.chroot|chroot\s+`),
		description: "Chroot manipulation - sandbox escape attempt",
		severity:    static_analysis_engine.SeverityCritical,
	},
	{
		pattern:     regexp.MustCompile(`(?i)mount\s+-o\s+bind|bindfs`),
		description: "Bind mount - potential sandbox escape",
		severity:    static_analysis_engine.SeverityHigh,
	},

	// Capability manipulation
	{
		pattern:     regexp.MustCompile(`(?i)cap_set|capset|setcap|getcap`),
		description: "Linux capability manipulation",
		severity:    static_analysis_engine.SeverityHigh,
	},

	// Kernel module loading
	{
		pattern:     regexp.MustCompile(`(?i)insmod|modprobe|rmmod|init_module`),
		description: "Kernel module manipulation - critical privilege escalation",
		severity:    static_analysis_engine.SeverityCritical,
	},

	// Cron/scheduled task manipulation
	{
		pattern:     regexp.MustCompile(`(?i)/etc/cron|crontab\s+-|schtasks`),
		description: "Scheduled task manipulation - persistence mechanism",
		severity:    static_analysis_engine.SeverityHigh,
	},

	// Service manipulation
	{
		pattern:     regexp.MustCompile(`(?i)systemctl\s+(enable|start|restart)|service\s+\w+\s+(start|restart)`),
		description: "System service manipulation",
		severity:    static_analysis_engine.SeverityHigh,
	},
}

// Dangerous imports that enable privilege escalation
var dangerousPrivilegeImports = map[string]string{
	"ctypes":    "Native code execution capability",
	"cffi":      "Foreign function interface - native code execution",
	"mmap":      "Memory mapping - potential sandbox escape",
	"resource":  "Resource limit manipulation",
	"grp":       "Group manipulation",
	"pwd":       "Password/user database access",
	"spwd":      "Shadow password access",
}

func (r *PrivilegeEscalationRule) Evaluate(ast interface{}) ([]static_analysis_engine.Finding, error) {
	py, ok := ast.(*python.PythonAST)
	if !ok {
		return nil, nil
	}

	var findings []static_analysis_engine.Finding
	r.walkTree(py.Tree.RootNode(), py.Source, &findings)

	return findings, nil
}

func (r *PrivilegeEscalationRule) walkTree(node *sitter.Node, source []byte, findings *[]static_analysis_engine.Finding) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// Check import statements for dangerous modules
	if nodeType == "import_statement" || nodeType == "import_from_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for module, desc := range dangerousPrivilegeImports {
			if regexp.MustCompile(`(?i)\b` + module + `\b`).MatchString(text) {
				*findings = append(*findings, static_analysis_engine.Finding{
					RuleID:   r.ID(),
					Message:  "Import of " + module + ": " + desc,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: static_analysis_engine.SeverityMedium,
				})
			}
		}
	}

	// Check for privilege escalation patterns
	if nodeType == "string" || nodeType == "call" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])

		for _, p := range privilegeEscalationPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, static_analysis_engine.Finding{
					RuleID:   r.ID(),
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
	static_analysis_engine.RegisterRule(static_analysis_engine.LanguagePython, NewPrivilegeEscalationRule())
}
