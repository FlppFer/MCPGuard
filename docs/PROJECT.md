# MCPGuard — Project Context

## Overview

MCPGuard is an automated security analysis pipeline for Model Context Protocol (MCP) server implementations. It is the **Go API** component described in the academic paper *"Pipeline Automatizada de Análise de Segurança para Implementações de Model Context Protocol (MCP)"* (Ferreira, Faculdade Impacta de Tecnologia) — see `docs/articles/MCPGuard.md`.

The system receives analysis requests via GitHub webhooks or direct API calls, clones the target repository, performs static rule-based analysis using tree-sitter AST parsing, and stores findings in S3-compatible object storage. Results are exposed through a REST API and can be consumed by GitHub Actions to comment on Pull Requests.

**Module path:** `github.com/FlppFer/MCPGuard`

---

## Architecture

MCPGuard follows a layered, service-oriented architecture with a clean separation between public interfaces, private implementations, and shared types:

```
cmd/api/              → Entrypoint, bootstrap, route registration
config/               → YAML-based configuration (embedded via go:embed)
docs/
  PROJECT.md          → This file — project context & architecture reference
  RULES_TAXONOMY.md   → Full mapping of 31 attacks to rule IDs
  articles/
    MCPGuard.md       → Our academic paper (MCPGuard pipeline)
    article1-5.pdf    → Base reference articles (see References section)
internal/
  controller/         → HTTP handlers (chi router)
  middleware/auth/    → Authentication strategies (webhook HMAC, API key)
  model/
    http/             → Request/response DTOs
    services/         → Service-layer DTOs (SourceFileDTO, etc.)
    repositories/     → Database entity (GORM model)
  repositories/
    db/               → SQLite persistence (GORM, with in-memory mock)
    obj_storage/      → Object storage (S3 + local filesystem mock)
  service/
    model/
      analysis_dtos.go           → Shared types: Finding, AnalysisResult, severity constants
      rule.go                    → Shared Rule interface
    git_webhook_service.go       → Core orchestration service
    agentic_analysis_service.go  → Placeholder for Python agentic worker
    static_analysis/
      service.go                 → Public Service interface + NewService() constructor
      engine.go                  → Private engine struct + EngineOption functional options
      rule_registry.go           → Global rule registry (keyed by language)
      static_analysis_service_test.go → Integration tests for the analysis service
      languages/python/
        parser.go                → tree-sitter Python AST parser
        rules/                   → 11 rule files covering 31 attack types (each with _test.go)
  utils/
    repo_download_utils.go       → Git clone + zip
    file_utils.go                → File walking, extension filtering, zipping
resources/
  test/               → Sample Python test files for rule validation
```

---

## Key Components

### 1. API & Routing (`cmd/api/`, `internal/controller/`)

- **Framework:** `go-chi/chi/v5`
- **Port:** `:8080`
- **Route groups:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/webhook/github` | Webhook (HMAC-SHA256) | GitHub push event handler |
| `POST` | `/v1/analysis` | API Key | Manual analysis trigger |
| `GET` | `/v1/analysis/{id}/status` | API Key | Poll analysis status |
| `GET` | `/v1/analysis/{id}/result` | API Key | Retrieve JSON findings |
| `POST` | `/v1/agentic_analysis` | API Key | Agentic analysis (not yet implemented) |
| `GET` | `/health` | None | Health check |

### 2. Authentication (`internal/middleware/auth/`)

Two strategies, both configured via environment variable names in YAML:

- **Webhook HMAC-SHA256:** Validates `X-Hub-Signature-256` header against the body using a shared secret (`GITHUB_WEBHOOK_SECRET` env var).
- **API Key:** Validates `X-API-Key` + `X-Client-ID` headers against a comma-separated key map (`MCPGUARD_API_KEYS` env var, format: `client_id:api_key,...`).

### 3. Analysis Orchestration (`internal/service/git_webhook_service.go`)

The `GitWebhookService` drives the full pipeline:

1. **Create** analysis entity in SQLite (status: `created`)
2. **Clone** target repository (shallow `git clone --depth 1`) to temp directory
3. **Zip** and **upload** source archive to object storage
4. **Parse** repository files (supported: `.py`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`)
5. **Run static analysis** asynchronously in a goroutine
6. **Upload** JSON findings to object storage (`analysis-results/{id}_static.json`)
7. **Update** entity status to `static_done`
8. **Return** analysis ID immediately (HTTP 202 Accepted)

### 4. Static Analysis (`internal/service/static_analysis/`)

The static analysis component uses a clean separation between its public interface and private implementation:

- **Public interface** (`service.go`): `Service` interface with a single `RunAnalysis()` method. The `NewService()` constructor accepts functional options and returns a `Service`.
- **Private implementation** (`engine.go`): `engine` struct implements `Service`. Manages AST parsing, rule evaluation, finding aggregation, and optional result persistence. Configured via `EngineOption` functional options (`WithOutputDir`, `WithPersistence`).
- **Shared types** (`internal/service/model/`):
  - `analysis_dtos.go` — `Finding`, `AnalysisResult`, and severity constants (`critical`, `high`, `medium`, `low`, `info`)
  - `rule.go` — `Rule` interface (`ID()`, `Description()`, `AppliesToLanguage()`, `Evaluate()`)
- **Rule registry** (`rule_registry.go`): Global `map[string][]model.Rule` keyed by language string. Rules self-register via `init()` functions using `RegisterRule()`.
- **AST parsing**: Uses `go-tree-sitter` with the Python grammar to produce a concrete syntax tree (`languages/python/parser.go`).

### 5. Security Rules (31 attack types)

Rules are based on the MCPLib taxonomy [1] and organized into 11 rule files under `internal/service/static_analysis/languages/python/rules/`:

| Rule File | Category |
|-----------|----------|
| `python_rule_tool_poisoning.go` | Rug Pull, Tool Preference manipulation |
| `python_rule_file_operations.go` | File Addition/Deletion/Modification/Retrieval |
| `python_rule_command_injection.go` | Command Injection (os.system, subprocess, eval) |
| `python_rule_remote_attacks.go` | Remote Listener, Remote Code Execution |
| `python_rule_multi_tool_attack.go` | Shadowing, Coverage, Obfuscation, Forced Exec, Coordination, Infectious |
| `python_rule_indirect_injection.go` | Webpage Poison, Malicious Project, Tool Return |
| `python_rule_malicious_user.go` | Tool Registration, Data Injection, Token Theft, Code Leakage, Installer Spoofing |
| `python_rule_privilege_escalation.go` | Privilege Escalation, Sandbox Escape |
| `python_rule_llm_attacks.go` | Jailbreak, Prompt Leakage, Hallucination, Backdoor, Goal Hijack, SQL Injection |
| `python_rule_credential_theft.go` | Credential/Token Theft (supplementary) |
| `python_rule_context_poisoning.go` | Context Manipulation (supplementary) |

Each rule file has a corresponding `_test.go` file. Test fixtures live in `resources/test/`.

See `docs/RULES_TAXONOMY.md` for the full mapping of all 31 attacks to rule IDs.

### 6. Persistence

- **Database:** SQLite via GORM (`internal/repositories/db/`). Supports mock mode (in-memory SQLite) and file-based mode. Entity: `AnalysisEntity` with status tracking and timestamps.
- **Object Storage:** S3-compatible via AWS SDK v2 (`internal/repositories/obj_storage/`). Supports mock mode (local filesystem) and production S3. Stores source archives and JSON result files.

### 7. Analysis Status Lifecycle

```
created → downloaded → static_analysis_started → static_done
                                                ↘ static_analysis_failed
       → clone_failed
       → storage_upload_failed
       → parse_failed
```

Full status enum (defined in `AnalysisEntity`): `created`, `downloading_repo`, `uploading_source`, `parsing_files`, `static_analysis_running`, `static_analysis_done`, `waiting_agent_analysis`, `agent_analysis_running`, `agent_analysis_done`, `completed`, `failed`.

---

## Configuration

Configuration is loaded from embedded YAML files selected by the `SCOPE` environment variable:

| Scope | File | Database | Storage |
|-------|------|----------|---------|
| `local` / `default` | `config/default.yaml` | In-memory SQLite (mock) | Local filesystem (mock) |
| `prod` / `production` | `config/prod.yaml` | File-based SQLite | AWS S3 |

### Required Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_WEBHOOK_SECRET` | Shared secret for GitHub webhook HMAC-SHA256 verification |
| `MCPGUARD_API_KEYS` | API key pairs for direct API access (format: `client_id:api_key,...`) |
| `SCOPE` | (Optional) Selects config profile (`local`, `prod`). Defaults to `local`. |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.25+ |
| HTTP Router | go-chi/chi v5 |
| AST Parsing | go-tree-sitter (Python grammar) |
| Database | SQLite via GORM |
| Object Storage | AWS S3 SDK v2 (with local mock) |
| UUID Generation | google/uuid |
| Config Format | YAML (embedded via `go:embed`) |
| Testing | go test + LocalStack (for S3 integration tests) |

---

## Supported File Types for Analysis

| Extension | Language Key |
|-----------|-------------|
| `.py` | `python` |
| `.json` | `json` |
| `.yaml`, `.yml` | `yaml` |
| `.toml` | `toml` |
| `.md` | `markdown` |

Currently, only Python has active rule-based analysis via tree-sitter AST. Other file types are parsed but have no registered rules yet.

---

## Not Yet Implemented

- **Agentic Analysis:** The `agentic_analysis_controller.go` and `agentic_analysis_service.go` are stubs. The planned Python-based AI agent worker (described in the MCPGuard article) that performs semantic analysis via LLMs is not yet integrated.
- **RabbitMQ Message Queue:** The article describes a message queue for scalability; the current implementation runs analysis synchronously in goroutines.
- **GitHub Actions Integration:** The CI/CD feedback loop (posting analysis results as PR comments) is not yet implemented in this codebase.
- **Docker Containerization:** No Dockerfile or docker-compose is present yet.
- **Metrics & Observability:** Prometheus + Grafana stack described in the article is not yet integrated.
- **Multi-language Rules:** Only Python rules exist; the rule registry supports language-keyed expansion.

---

## Base Articles & References

The MCPGuard article (`docs/articles/MCPGuard.md`) draws on the following base research articles (converted `.md` versions at repo root, original PDFs under `docs/articles/`):

| # | File | Title | Authors | Key Contribution to MCPGuard |
|---|------|-------|---------|------------------------------|
| 1 | `article1.md` / `article1.pdf` | *Systematic Analysis of MCP Security* | Guo, Y. et al. (arXiv:2508.12538) | **Primary reference.** Provides the MCPLib attack taxonomy with 31 attack types in 4 categories (Direct Tool Injection, Indirect Tool Injection, Malicious User Attacks, LLM Inherent Attacks). MCPGuard's 11 rule files and `RULES_TAXONOMY.md` directly implement detection for all 31 attacks. |
| 2 | `article2.md` / `article2.pdf` | *Towards Understanding Sycophancy in Language Models* | Sharma, M. et al. (Anthropic) | Foundational research on LLM sycophancy — the tendency of AI models to agree with user beliefs over truth. Referenced by article 1 as a core vulnerability that MCP Tool Poisoning Attacks exploit (agents blindly trust tool descriptions). |
| 3 | `article3.md` / `article3.pdf` | *Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions* | Hou, X. et al. (Huazhong Univ.) | Comprehensive MCP landscape survey. Defines the MCP server lifecycle (4 phases, 16 activities) and a threat taxonomy with 4 attacker types and 16 threat scenarios. Informs MCPGuard's architectural understanding of MCP and its broader threat model. |
| 4 | `article4.md` / `article4.pdf` | *Enterprise-Grade Security for the Model Context Protocol (MCP): Frameworks and Mitigation Strategies* | Narajala, V.S. & Habler, I. (AWS / Intuit) | Proposes enterprise security frameworks using MAESTRO, Zero Trust Architecture, and defense-in-depth for MCP. Provides context for MCPGuard's positioning as a practical tool in the broader MCP security ecosystem. |
| 5 | `article5.md` / `article5.pdf` | *MCP Security Bench (MSB): Benchmarking Attacks Against Model Context Protocol in LLM Agents* | Zhang, D. et al. (BUPT / UCSB) | First end-to-end MCP security benchmark. Introduces 12 attack types across the full tool-use pipeline (task planning, tool invocation, response handling) with 2,000 attack instances. Complements MCPGuard's static analysis approach with a dynamic evaluation perspective. |

### Additional References

- Anthropic (2024) — *Model Context Protocol Specification*: https://modelcontextprotocol.io/specification
- Invariant Labs (2024) — *MCP Security Audit: Tool Poisoning Attacks*: https://invariantlabs.ai/blog/mcp-security-audit