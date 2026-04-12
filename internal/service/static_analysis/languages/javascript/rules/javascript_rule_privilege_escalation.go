package rules

import (
	"regexp"

	"github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/javascript"
	sitter "github.com/smacker/go-tree-sitter"
)

// JSPrivilegeEscalationRule detects privilege escalation and sandbox escape attempts in JS/TS.
// Based on MCP Attack Taxonomy: Malicious User Attack (III-C2, III-C7).
type JSPrivilegeEscalationRule struct{}

func NewJSPrivilegeEscalationRule() model.Rule { return &JSPrivilegeEscalationRule{} }

func (r *JSPrivilegeEscalationRule) ID() string               { return "MCP-JS-PE-001" }
func (r *JSPrivilegeEscalationRule) Description() string       { return "Detects privilege escalation and sandbox escape attempts in JavaScript/TypeScript" }
func (r *JSPrivilegeEscalationRule) AppliesToLanguage() string { return "javascript" }

var jsPrivilegeEscalationPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	// Direct privilege escalation
	{regexp.MustCompile(`(?i)(sudo|su\s+-|runas|doas)\s+`), "Privilege elevation command detected", model.SeverityCritical},
	{regexp.MustCompile(`(?i)process\.(setuid|setgid|seteuid|setegid)\s*\(`), "Node.js UID/GID manipulation", model.SeverityCritical},

	// Sandbox escape — native code
	{regexp.MustCompile(`(?i)require\s*\(\s*['"]ffi-napi['"]\s*\)`), "FFI native binding — potential sandbox escape", model.SeverityHigh},
	{regexp.MustCompile(`(?i)require\s*\(\s*['"]node-ffi['"]\s*\)`), "FFI native binding — potential sandbox escape", model.SeverityHigh},
	{regexp.MustCompile(`(?i)require\s*\(\s*['"]ref-napi['"]\s*\)`), "Native memory reference — potential sandbox escape", model.SeverityHigh},
	{regexp.MustCompile(`(?i)process\.dlopen\s*\(`), "Native addon loading — potential sandbox escape", model.SeverityCritical},
	{regexp.MustCompile(`(?i)require\s*\(\s*['"].*\.node['"]\s*\)`), "Native .node addon loading — potential sandbox escape", model.SeverityHigh},

	// Process/memory access
	{regexp.MustCompile(`(?i)/proc/(self|[0-9]+)/(mem|maps|fd)`), "Process memory access — potential sandbox escape", model.SeverityCritical},
	{regexp.MustCompile(`(?i)process\.(kill|exit|abort)\s*\(`), "Process termination — potential denial of service", model.SeverityHigh},

	// Container/virtualization escape
	{regexp.MustCompile(`(?i)/var/run/docker\.sock`), "Docker socket access — container escape vector", model.SeverityCritical},
	{regexp.MustCompile(`(?i)\.dockerenv|/proc/1/cgroup`), "Container detection — may be used for escape attempts", model.SeverityMedium},
	{regexp.MustCompile(`(?i)(nsenter|unshare|setns)`), "Namespace manipulation — container escape vector", model.SeverityCritical},

	// File system escape
	{regexp.MustCompile(`(?i)\.\./\.\./|\.\.\\\.\.\\`), "Path traversal pattern — potential sandbox escape", model.SeverityHigh},

	// Cron/scheduled task manipulation
	{regexp.MustCompile(`(?i)/etc/cron|crontab\s+-|schtasks`), "Scheduled task manipulation — persistence mechanism", model.SeverityHigh},

	// Service manipulation
	{regexp.MustCompile(`(?i)systemctl\s+(enable|start|restart)|service\s+\w+\s+(start|restart)`), "System service manipulation", model.SeverityHigh},

	// Kernel module loading
	{regexp.MustCompile(`(?i)insmod|modprobe|rmmod`), "Kernel module manipulation — critical privilege escalation", model.SeverityCritical},

	// V8/Node sandbox escape
	{regexp.MustCompile(`(?i)vm\.runInThisContext\s*\(`), "vm.runInThisContext — can escape sandbox", model.SeverityCritical},
	{regexp.MustCompile(`(?i)vm2|isolated-vm`), "VM sandbox library — verify escape protections", model.SeverityMedium},
}

// Dangerous imports that enable privilege escalation in Node.js
var jsPrivilegeImports = map[string]string{
	"child_process": "Child process execution capability",
	"cluster":       "Cluster module — process forking",
	"worker_threads": "Worker threads — parallel execution",
	"v8":            "V8 engine access — low-level control",
	"perf_hooks":    "Performance hooks — timing side-channel risk",
}

func (r *JSPrivilegeEscalationRule) Evaluate(ast interface{}) ([]model.Finding, error) {
	js, ok := ast.(*javascript.JavaScriptAST)
	if !ok {
		return nil, nil
	}
	var findings []model.Finding
	r.walkTree(js.Tree.RootNode(), js.Source, &findings)
	return findings, nil
}

func (r *JSPrivilegeEscalationRule) walkTree(node *sitter.Node, source []byte, findings *[]model.Finding) {
	if node == nil {
		return
	}
	nodeType := node.Type()

	// Check require() calls for dangerous modules
	if nodeType == "call_expression" {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			funcText := string(source[funcNode.StartByte():funcNode.EndByte()])
			if funcText == "require" {
				argsNode := node.ChildByFieldName("arguments")
				if argsNode != nil {
					argsText := string(source[argsNode.StartByte():argsNode.EndByte()])
					for mod, desc := range jsPrivilegeImports {
						if regexp.MustCompile(`['"]` + mod + `['"]`).MatchString(argsText) {
							*findings = append(*findings, model.Finding{
								RuleID:   r.ID(),
								Message:  "Import of " + mod + ": " + desc,
								Line:     int(node.StartPoint().Row) + 1,
								Snippet:  truncateSnippet(string(source[node.StartByte():node.EndByte()]), 200),
								Severity: model.SeverityMedium,
							})
						}
					}
				}
			}
		}
	}

	// Check import declarations for dangerous modules
	if nodeType == "import_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for mod, desc := range jsPrivilegeImports {
			if regexp.MustCompile(`['"]` + mod + `['"]`).MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  "Import of " + mod + ": " + desc,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: model.SeverityMedium,
				})
			}
		}
	}

	// Check for privilege escalation patterns
	if nodeType == "string" || nodeType == "template_string" || nodeType == "call_expression" || nodeType == "expression_statement" {
		text := string(source[node.StartByte():node.EndByte()])
		for _, p := range jsPrivilegeEscalationPatterns {
			if p.pattern.MatchString(text) {
				*findings = append(*findings, model.Finding{
					RuleID:   r.ID(),
					Message:  p.description,
					Line:     int(node.StartPoint().Row) + 1,
					Snippet:  truncateSnippet(text, 200),
					Severity: p.severity,
				})
			}
		}
	}

	for i := uint32(0); i < node.ChildCount(); i++ {
		r.walkTree(node.Child(int(i)), source, findings)
	}
}

func init() {
	static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewJSPrivilegeEscalationRule())
}
