# Task 7.1: JavaScript/TypeScript Rule Foundation

| Field | Value |
|-------|-------|
| **ID** | task-7.1 |
| **Phase** | 7 — Multi-Language Rule Expansion |
| **Priority** | Low |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

MCPGuard only analyzes Python files. MCP servers can also be written in JavaScript/TypeScript (the official MCP SDK is TypeScript-first). The rule registry supports multi-language keying, but no JS/TS parser or rules exist.

### Expected Behavior

1. JavaScript (`.js`) and TypeScript (`.ts`) files are parsed into ASTs using tree-sitter with the JavaScript grammar.
2. An initial set of security rules detects the highest-impact MCP attack patterns in JS/TS code.
3. Rules self-register under a `"javascript"` language key.
4. The file utils correctly map `.js` and `.ts` extensions to `"javascript"`.

### Acceptance Criteria

- `.js` and `.ts` files in analyzed repositories are processed by the static analysis engine.
- At least 3 initial rule files cover the most critical attack categories:
  - Command injection (`child_process.exec`, `eval()`)
  - File operations (`fs.readFile`, `fs.writeFile`, `fs.unlink`)
  - Tool poisoning (dynamic description modification)
- Each rule file has corresponding tests with JS fixture files.
- Existing Python analysis is unaffected.

---

## Technical Specification

### tree-sitter JavaScript Grammar

The `go-tree-sitter` ecosystem provides a JavaScript grammar. Add dependency:
```
github.com/smacker/go-tree-sitter
```
The JavaScript grammar covers both `.js` and `.ts` (TypeScript is a superset parsed with the same grammar for basic AST patterns; for full TS support, the TypeScript grammar would be needed separately).

### Create `internal/service/static_analysis/languages/javascript/parser.go`

```go
package javascript

import (
    sitter "github.com/smacker/go-tree-sitter"
    "github.com/smacker/go-tree-sitter/javascript"
)

// JavaScriptAST holds the parsed tree and original source for a JS/TS file.
type JavaScriptAST struct {
    Tree       *sitter.Tree
    Source     []byte
    SourcePath string
}

// ParseJavaScript parses JavaScript/TypeScript source code into an AST.
func ParseJavaScript(source []byte, filePath string) (*JavaScriptAST, error) {
    parser := sitter.NewParser()
    parser.SetLanguage(javascript.GetLanguage())

    tree, err := parser.ParseCtx(nil, nil, source)
    if err != nil {
        return nil, err
    }

    return &JavaScriptAST{
        Tree:       tree,
        Source:     source,
        SourcePath: filePath,
    }, nil
}
```

### Register Language Constant

In `internal/service/static_analysis/rule_registry.go`:

```go
const (
    LanguagePython     = "python"
    LanguageJavaScript = "javascript"  // NEW
)
```

### Update File Extension Mapping

In `internal/utils/file_utils.go`, add JS/TS extensions to the language mapping:

```go
// Add to the extension → language map
".js":  "javascript",
".ts":  "javascript",
".jsx": "javascript",
".tsx": "javascript",
```

### Update Engine to Use JS Parser

In `internal/service/static_analysis/engine.go`, the `parseAST` or file-processing logic needs to detect `language == "javascript"` and call `javascript.ParseJavaScript()` instead of the Python parser.

### Initial Rule Files

Create under `internal/service/static_analysis/languages/javascript/rules/`:

#### 1. `javascript_rule_command_injection.go`

Detects:
- `child_process.exec(...)`, `child_process.execSync(...)`
- `eval(...)`, `Function(...)()`
- `require('child_process')` with dynamic arguments
- Template literal interpolation in shell commands

Patterns (AST node types):
- `call_expression` with callee matching `exec`, `execSync`, `eval`
- `member_expression` with object `child_process`

#### 2. `javascript_rule_file_operations.go`

Detects:
- `fs.readFileSync`, `fs.writeFileSync`, `fs.unlinkSync`, `fs.rmdirSync`
- `fs.promises.readFile`, `fs.promises.writeFile`, `fs.promises.unlink`
- Path traversal patterns (`../`, sensitive paths like `/etc/passwd`)
- `fs.chmodSync`, `fs.chownSync`

#### 3. `javascript_rule_tool_poisoning.go`

Detects:
- Dynamic modification of tool descriptions (MCP SDK patterns)
- `server.tool(...)` with dynamic name/description
- Overwriting `description` property after tool registration
- Prototype pollution patterns (`__proto__`, `constructor.prototype`)

### Test Fixtures

Create under `resources/test/`:
- `test_command_injection.js`
- `test_file_operations.js`
- `test_tool_poisoning.js`

Each fixture should contain both vulnerable and safe code patterns for the rule to distinguish.

### Rule Registration Pattern

Same as Python rules — `init()` function:

```go
func init() {
    static_analysis.RegisterRule(static_analysis.LanguageJavaScript, NewCommandInjectionRule())
}
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/service/static_analysis/languages/javascript/parser.go` | JS AST parser |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_command_injection.go` | Command injection detection |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_command_injection_test.go` | Tests |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_file_operations.go` | File operation detection |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_file_operations_test.go` | Tests |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_tool_poisoning.go` | Tool poisoning detection |
| `internal/service/static_analysis/languages/javascript/rules/javascript_rule_tool_poisoning_test.go` | Tests |
| `resources/test/test_command_injection.js` | JS test fixture |
| `resources/test/test_file_operations.js` | JS test fixture |
| `resources/test/test_tool_poisoning.js` | JS test fixture |

### Files to Modify

| File | Change |
|------|--------|
| `internal/service/static_analysis/rule_registry.go` | Add `LanguageJavaScript` constant |
| `internal/utils/file_utils.go` | Add `.js`, `.ts`, `.jsx`, `.tsx` extension mappings |
| `internal/service/static_analysis/engine.go` | Add JS parser dispatch |
| `cmd/api/setup/resources.go` | Add blank import for JS rules package to trigger `init()` |

### Testing

- Parse a JS file → verify AST is returned.
- Run command injection rule on `test_command_injection.js` → verify findings.
- Run file operations rule on `test_file_operations.js` → verify findings.
- Run tool poisoning rule on `test_tool_poisoning.js` → verify findings.
- Run full analysis on a repo containing both `.py` and `.js` → verify both languages produce findings.
- Existing Python tests pass unchanged.
