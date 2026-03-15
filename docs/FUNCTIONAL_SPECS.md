# MCPGuard — Functional Specifications

> Version: 1.0 — Aligned with codebase as of March 2026

---

## 1. Purpose

MCPGuard is an automated security analysis pipeline that audits Model Context Protocol (MCP) server implementations for known vulnerabilities, permission abuse, and contextual poisoning patterns. It targets development teams building MCP servers who need early detection of security risks before deployment.

---

## 2. Actors

| Actor | Description |
|-------|-------------|
| **GitHub** | Sends push event webhooks when code is pushed to a repository |
| **Developer / CI System** | Triggers analysis manually via the REST API using API Key authentication |
| **MCPGuard API** | Receives requests, orchestrates analysis, stores and serves results |
| **Static Analysis Engine** | Parses source code, applies security rules, generates findings |
| **Agentic Analysis Worker** *(planned)* | Python-based AI agent for semantic analysis via LLMs |

---

## 3. Core Use Cases

### UC-01: Trigger Analysis via GitHub Webhook

**Actor:** GitHub (push event)

**Preconditions:** Webhook is configured on the repository with the correct HMAC-SHA256 secret.

**Flow:**
1. GitHub sends a `POST /v1/webhook/github` with the push payload and `X-Hub-Signature-256` header.
2. MCPGuard validates the HMAC-SHA256 signature against the request body.
3. MCPGuard extracts the repository URL, branch, and commit SHA from the payload.
4. MCPGuard creates an analysis entity (status: `created`) and returns HTTP 202 with the `analysis_id`.
5. In the background:
   a. Clone the repository (shallow, depth 1) to a temp directory.
   b. Zip the repository and upload the archive to object storage.
   c. Parse repository files (filter supported extensions: `.py`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`).
   d. Run static analysis on all parsed files.
   e. Upload JSON findings to object storage.
   f. Update analysis status to `static_analysis_done`.

**Postconditions:** Analysis findings are stored and accessible via the results endpoint.

**Error Handling:**
- Invalid signature → HTTP 401 Unauthorized
- Clone failure → status set to `failed`, error message persisted
- Parse failure → status set to `failed`
- Analysis failure → status set to `failed`

---

### UC-02: Trigger Analysis via Direct API Call

**Actor:** Developer / CI System

**Preconditions:** Valid API Key and Client ID configured.

**Flow:**
1. Client sends `POST /v1/analysis` with `X-API-Key` and `X-Client-ID` headers and a JSON body: `{ "repo_url": "...", "branch": "...", "commit": "..." }`.
2. MCPGuard validates the API Key + Client ID pair.
3. Same background processing as UC-01 (steps 4–5).

**Postconditions:** Same as UC-01.

---

### UC-03: Check Analysis Status

**Actor:** Developer / CI System

**Flow:**
1. Client sends `GET /v1/analysis/{id}/status` with API Key auth.
2. MCPGuard looks up the analysis entity by ID.
3. Returns the current status, timestamps, and error message (if any).

**Response:** `{ "analysis_id": "...", "status": "static_analysis_done", ... }`

**Error Handling:**
- Analysis not found → HTTP 404

---

### UC-04: Retrieve Analysis Results

**Actor:** Developer / CI System

**Flow:**
1. Client sends `GET /v1/analysis/{id}/result` with API Key auth.
2. MCPGuard retrieves the JSON findings from object storage.
3. Returns the full `AnalysisResult` with all findings.

**Response:**
```json
{
  "analysis_id": "uuid",
  "files_analyzed": 12,
  "findings": [
    {
      "rule_id": "MCP-DTI-002",
      "message": "Command injection via os.system()",
      "file_path": "server.py",
      "line": 42,
      "severity": "high",
      "snippet": "os.system(user_input)"
    }
  ]
}
```

**Error Handling:**
- Analysis not found → HTTP 404
- Analysis not yet complete → HTTP 409 or appropriate status

---

### UC-05: Health Check

**Actor:** Any (no authentication)

**Flow:**
1. Client sends `GET /health`.
2. MCPGuard returns HTTP 200.

---

## 4. Security Analysis — Functional Behavior

### 4.1 Scope of Analysis

MCPGuard performs **static, rule-based** analysis. It does **not** execute the target code. Analysis operates on:

- **AST-level patterns** — tree-sitter parses Python source into a concrete syntax tree; rules walk the tree matching node types and content.
- **Regex-level patterns** — complementary regex matching on source text for patterns not efficiently captured by AST alone.

### 4.2 Supported Languages

| Language | AST Parsing | Active Rules |
|----------|------------|-------------|
| Python | Yes (tree-sitter) | 31 attack patterns across 11 rule files |
| JSON | File read only | None (planned) |
| YAML | File read only | None (planned) |
| TOML | File read only | None (planned) |
| Markdown | File read only | None (planned) |

### 4.3 Attack Taxonomy Coverage

All 31 attack types from the MCPLib taxonomy (Guo et al., 2025) are covered, organized into four categories:

**Category I — Direct Tool Injection (14 attacks)**

| Attack | Rule File |
|--------|-----------|
| File-Based Injection (Addition, Deletion, Modification, Retrieval) | `python_rule_file_operations.go` |
| Rug Pull | `python_rule_tool_poisoning.go` |
| Remote Listener | `python_rule_remote_attacks.go` |
| Command Injection | `python_rule_command_injection.go` |
| Remote Code Execution | `python_rule_remote_attacks.go` |
| Shadowing, Tool Coverage, Tool Preference Manipulation | `python_rule_multi_tool_attack.go` |
| Functional Obfuscation, Forced Execution | `python_rule_multi_tool_attack.go` |
| Multi-Tool Coordination, Infectious | `python_rule_multi_tool_attack.go` |

**Category II — Indirect Tool Injection (3 attacks)**

| Attack | Rule File |
|--------|-----------|
| Webpage Poison | `python_rule_indirect_injection.go` |
| Malicious Project Installation | `python_rule_indirect_injection.go` |
| MCP Tool Return | `python_rule_indirect_injection.go` |

**Category III — Malicious User Attacks (7 attacks)**

| Attack | Rule File |
|--------|-----------|
| Malicious Tool Registration | `python_rule_malicious_user.go` |
| Privilege Escalation, Sandbox Escape | `python_rule_privilege_escalation.go` |
| Data Injection, Token Theft, Code Leakage, Installer Spoofing | `python_rule_malicious_user.go` |
| Credential Theft (supplementary) | `python_rule_credential_theft.go` |

**Category IV — LLM Inherent Attacks (6 attacks)**

| Attack | Rule File |
|--------|-----------|
| Jailbreak, Prompt Leakage, Hallucination | `python_rule_llm_attacks.go` |
| Backdoor, Goal Hijack, SQL Injection | `python_rule_llm_attacks.go` |

**Supplementary:**

| Attack | Rule File |
|--------|-----------|
| Context Poisoning / Manipulation | `python_rule_context_poisoning.go` |

See `docs/RULES_TAXONOMY.md` for the complete mapping of all 31 attacks to specific rule IDs.

### 4.4 Severity Classification

Each finding is classified with one of five severity levels:

| Severity | Description |
|----------|-------------|
| `critical` | Direct exploitation with high impact (e.g., RCE, global namespace manipulation) |
| `high` | Significant risk requiring immediate attention (e.g., command injection, credential access) |
| `medium` | Moderate risk, may require context to determine exploitability |
| `low` | Minor risk or informational pattern that may indicate bad practice |
| `info` | Informational — pattern detected but not necessarily a vulnerability |

### 4.5 Finding Structure

Every finding includes:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique identifier linking to the MCPLib taxonomy (e.g., `MCP-DTI-002`) |
| `message` | Human-readable description of the detected issue |
| `file_path` | Relative path to the file within the analyzed repository |
| `line` | Line number where the issue was detected (1-indexed) |
| `severity` | One of: `critical`, `high`, `medium`, `low`, `info` |
| `snippet` | Relevant code snippet from the source (truncated to 200 chars) |

---

## 5. Analysis Pipeline — End-to-End Flow

```
┌─────────────┐      ┌───────────────┐      ┌──────────────────┐
│   GitHub     │─────▶│  MCPGuard API │─────▶│  Object Storage  │
│   Webhook    │ POST │  (Go / chi)   │      │  (S3 / Local)    │
└─────────────┘      └───────┬───────┘      └──────────────────┘
                             │                        ▲
                             ▼                        │
                     ┌───────────────┐                │
                     │    SQLite     │                │
                     │  (GORM)      │                │
                     └───────────────┘                │
                             │                        │
                             ▼                        │
                     ┌───────────────┐                │
                     │  Git Clone    │                │
                     │  + Zip + Upload ──────────────┘
                     └───────┬───────┘
                             │
                             ▼
                     ┌───────────────┐
                     │  File Parser  │
                     │  (.py filter) │
                     └───────┬───────┘
                             │
                             ▼
                     ┌───────────────────────┐
                     │  Static Analysis      │
                     │  Engine               │
                     │  ┌─────────────────┐  │
                     │  │ tree-sitter AST │  │
                     │  └────────┬────────┘  │
                     │           ▼           │
                     │  ┌─────────────────┐  │
                     │  │ 31 Rules × 11   │  │
                     │  │ Rule Files      │  │
                     │  └────────┬────────┘  │
                     │           ▼           │
                     │  ┌─────────────────┐  │
                     │  │ AnalysisResult  │──┼──▶ Upload JSON to S3
                     │  │ (Findings)      │  │
                     │  └─────────────────┘  │
                     └───────────────────────┘
```

### Pipeline Steps

| Step | Action | Status After |
|------|--------|-------------|
| 1 | Receive request, validate auth | `created` |
| 2 | Clone repository (shallow, depth 1) | `downloading_repo` |
| 3 | Zip source, upload archive to S3 | `uploading_source` |
| 4 | Walk directory, filter supported files, read content | `parsing_files` |
| 5 | Run static analysis (AST parse + rule evaluation) | `static_analysis_running` |
| 6 | Upload JSON findings to S3 | `static_analysis_done` |
| 7 | *(Planned)* Queue agentic analysis | `waiting_agent_analysis` |
| 8 | *(Planned)* AI agent semantic analysis | `agent_analysis_done` |
| 9 | *(Planned)* Merge results | `completed` |

---

## 6. Non-Functional Requirements

### 6.1 Performance
- Analysis is performed **asynchronously** — the API returns HTTP 202 immediately.
- Current implementation uses Go goroutines for background processing.
- *(Planned)* RabbitMQ for horizontal scaling with multiple workers.

### 6.2 Reliability
- Analysis status is persisted in SQLite — survives API restarts.
- Failed analyses are tracked with error messages.
- *(Planned)* Message queue persistence ensures no job loss.

### 6.3 Security
- Webhook authentication via HMAC-SHA256 (prevents forged requests).
- API Key authentication for direct access.
- Secrets managed via environment variables (never hardcoded).
- *(Planned)* TLS for all communication, Docker isolation for analyzed code.

### 6.4 Extensibility
- New languages: Add a tree-sitter grammar + parser, register rules under a new language key.
- New rules: Implement `model.Rule` interface, self-register via `init()`.
- Rule registry supports any number of languages and rules.

### 6.5 Configuration
- Two deployment profiles: `local` (mocks) and `prod` (real services).
- Profile selected via `SCOPE` environment variable.
- All infrastructure dependencies (DB, storage) are abstracted behind interfaces.

---

## 7. Planned Features (Not Yet Implemented)

| Feature | Description | Status |
|---------|-------------|--------|
| **Agentic Analysis** | Python-based AI agent using LLMs for semantic security analysis | Stub exists |
| **RabbitMQ Queue** | Async job distribution for horizontal scaling | Not started |
| **GitHub Actions Integration** | Auto-comment analysis findings on Pull Requests | Not started |
| **Docker Containerization** | Isolate components, reproducible deployments | Not started |
| **Prometheus + Grafana** | Metrics collection, dashboards, alerting | Not started |
| **Multi-language Support** | Extend rules beyond Python (JS, TypeScript, etc.) | Registry supports it, no rules yet |

---

## 8. Acceptance Criteria (Implemented Features)

| Criterion | Verified By |
|-----------|-------------|
| API accepts GitHub push webhooks and validates HMAC-SHA256 | Integration test + manual |
| API accepts manual analysis requests with API Key auth | Integration test + manual |
| Repository is cloned, zipped, and uploaded to storage | Pipeline flow |
| Python files are parsed into ASTs using tree-sitter | Unit tests in rule `_test.go` files |
| All 31 MCPLib attack patterns are detected by rules | 11 rule test files with full coverage |
| Findings include rule_id, message, file_path, line, severity, snippet | `assertFindingComplete` in tests |
| Analysis status is tracked end-to-end in SQLite | Status lifecycle flow |
| Results are persisted as JSON in object storage | Pipeline flow |
| Results are retrievable via REST API | `GET /v1/analysis/{id}/result` |
| Application compiles and builds successfully | `go build ./...` |
