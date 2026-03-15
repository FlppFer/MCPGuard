# MCPGuard — Project Context

## Overview

MCPGuard is an automated security analysis pipeline for Model Context Protocol (MCP) server implementations. It is the **Go API** component described in the academic paper *"Pipeline Automatizada de Análise de Segurança para Implementações de Model Context Protocol (MCP)"* (Ferreira, Faculdade Impacta de Tecnologia).

The system receives analysis requests via GitHub webhooks or direct API calls, clones the target repository, performs static rule-based analysis using tree-sitter AST parsing, and stores findings in S3-compatible object storage. Results are exposed through a REST API and can be consumed by GitHub Actions to comment on Pull Requests.

**Module path:** `github.com/FlppFer/MCPGuard`

---

## Architecture

MCPGuard follows a layered, service-oriented architecture:

```
cmd/api/              → Entrypoint, bootstrap, route registration
config/               → YAML-based configuration (embedded via go:embed)
internal/
  controller/         → HTTP handlers (chi router)
  middleware/auth/    → Authentication strategies (webhook HMAC, API key)
  model/
    http/             → Request/response DTOs
    services/         → Service-layer DTOs
    repositories/     → Database entity (GORM model)
  repositories/
    db/               → SQLite persistence (GORM, with in-memory mock)
    obj_storage/      → Object storage (S3 + local filesystem mock)
  service/
    git_webhook_service.go       → Core orchestration service
    agentic_analysis_service.go  → Placeholder for Python agentic worker
    static_analysis/
      rule.go                    → Rule interface & global registry
      finding.go                 → Finding struct & severity constants
      static_analysis_engine.go  → StaticAnalysisService interface
      static_analysis_engine_impl.go → Engine implementation
      languages/python/
        parser.go                → tree-sitter Python AST parser
        rules/                   → 11 rule files covering 31 attack types
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

### 4. Static Analysis Engine (`internal/service/static_analysis/`)

- **Interface:** `StaticAnalysisService` with `Analyze()` and `RunAnalysis()` methods.
- **Rule registry:** Global map keyed by language string; rules self-register via `init()` functions.
- **AST parsing:** Uses `go-tree-sitter` with the Python grammar to produce a concrete syntax tree.
- **Finding model:** Each finding includes `rule_id`, `message`, `file_path`, `line`, `severity`, and `snippet`.
- **Functional options:** `WithOutputDir(dir)` and `WithPersistence(bool)` configure the engine.

### 5. Security Rules (31 attack types)

Rules are based on the MCPLib taxonomy (arXiv:2508.12538, Guo et al. 2025) and organized into 11 rule files under `internal/service/static_analysis/languages/python/rules/`:

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

**Severity levels:** `critical`, `high`, `medium`, `low`, `info`

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

- **Agentic Analysis:** The `agentic_analysis_controller.go` and `agentic_analysis_service.go` are stubs. The planned Python-based AI agent worker (described in the article) that performs semantic analysis via LLMs is not yet integrated.
- **RabbitMQ Message Queue:** The article describes a message queue for scalability; the current implementation runs analysis synchronously in goroutines.
- **GitHub Actions Integration:** The CI/CD feedback loop (posting analysis results as PR comments) is not yet implemented in this codebase.
- **Docker Containerization:** No Dockerfile or docker-compose is present yet.
- **Multi-language Rules:** Only Python rules exist; the rule registry supports language-keyed expansion.

---

## References

- Paper: *"Pipeline Automatizada de Análise de Segurança para Implementações de Model Context Protocol (MCP)"* — Ferreira, F.A.D. (Faculdade Impacta de Tecnologia)
- Attack Taxonomy: *"Systematic Analysis of MCP Security"* — Guo et al. (arXiv:2508.12538)
- MCPLib: MCP Attack Library with 31 attack implementations