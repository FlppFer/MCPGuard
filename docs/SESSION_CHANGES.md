# MCPGuard — Session Changes Review

> **Date**: April 4–5, 2026
> **Scope**: Phases 4–7 (uncommitted changes since `623be42`)
> **Build**: ✅ Clean | **Tests**: ✅ All passing

---

## Phase 4: Message Queue (RabbitMQ)

**Task Spec**: [`docs/tasks/task-4.1-message-queue-abstraction.md`](../docs/tasks/task-4.1-message-queue-abstraction.md), [`task-4.2-pipeline-queue-refactor.md`](../docs/tasks/task-4.2-pipeline-queue-refactor.md), [`task-4.3-docker-rabbitmq.md`](../docs/tasks/task-4.3-docker-rabbitmq.md)

### New Files
| File | Purpose |
|------|---------|
| `internal/messaging/publisher.go` | `MessagePublisher` interface + RabbitMQ factory |
| `internal/messaging/rabbitmq_publisher.go` | RabbitMQ publisher implementation |
| `internal/messaging/noop_publisher.go` | No-op publisher for local/test mode |
| `internal/messaging/noop_publisher_test.go` | No-op publisher tests |
| `internal/messaging/messages.go` | Message types and queue constants |
| `internal/worker/static_analysis_worker.go` | Async worker consumer for queue-based analysis |

### Modified Files
| File | Change |
|------|--------|
| `cmd/api/main.go` | Worker mode entrypoint, graceful shutdown for queue consumer |
| `cmd/api/setup/resources.go` | Wire `MessagePublisher` into service layer |
| `cmd/api/setup/routes.go` | Route setup adjustments |
| `config/config.go` | Added `MessagingConfig` struct |
| `config/default.yaml` | Added `messaging` section (disabled by default) |
| `config/prod.yaml` | Added `messaging` section (enabled) |
| `docker-compose.yaml` | Added `rabbitmq` + `mcpguard-worker` services under `queue` profile |
| `internal/service/git_webhook_service.go` | Queue-based analysis dispatch via publisher |
| `go.mod` / `go.sum` | Added `rabbitmq/amqp091-go` dependency |

---

## Phase 5: Observability

**Task Spec**: [`docs/tasks/task-5.1-prometheus-metrics.md`](../docs/tasks/task-5.1-prometheus-metrics.md), [`task-5.2-grafana-dashboard.md`](../docs/tasks/task-5.2-grafana-dashboard.md)

### New Files
| File | Purpose |
|------|---------|
| `internal/metrics/analysis_metrics.go` | Prometheus counters & histograms (`mcpguard_analyses_total`, `mcpguard_findings_total`, `mcpguard_analysis_duration_seconds`, `http_requests_total`, `http_request_duration_seconds`) |
| `internal/middleware/metrics.go` | HTTP middleware for request metrics |
| `deploy/prometheus/prometheus.yml` | Prometheus scrape config (15s interval, target `mcpguard-api:8080`) |
| `deploy/grafana/dashboards/mcpguard.json` | Grafana dashboard — 6 panels (analysis rate, findings by severity, duration percentiles, HTTP rate, error rate, latency) |
| `deploy/grafana/provisioning/datasources.yaml` | Auto-provision Prometheus datasource |
| `deploy/grafana/provisioning/dashboards.yaml` | Auto-provision dashboard from JSON |

### Modified Files
| File | Change |
|------|--------|
| `docker-compose.yaml` | Added `prometheus` + `grafana` services under `observability` profile |
| `cmd/api/setup/routes.go` | `/metrics` endpoint + metrics middleware registration |
| `internal/service/git_webhook_service.go` | Metrics instrumentation on analysis start/complete/findings |
| `go.mod` / `go.sum` | Added `prometheus/client_golang` dependency |

---

## Phase 6: GitHub Actions PR Integration

**Task Spec**: [`docs/tasks/task-6.1-pr-comment-service.md`](../docs/tasks/task-6.1-pr-comment-service.md), [`task-6.2-actions-workflow.md`](../docs/tasks/task-6.2-actions-workflow.md), [`task-6.3-pr-payload.md`](../docs/tasks/task-6.3-pr-payload.md)

### New Files
| File | Purpose |
|------|---------|
| `internal/service/github_integration/pr_comment_service.go` | Posts analysis findings as PR comments via GitHub API |
| `internal/service/github_integration/markdown_formatter.go` | Formats `AnalysisResult` into Markdown for PR comments |
| `internal/service/github_integration/markdown_formatter_test.go` | Formatter unit tests |
| `.github/workflows/mcpguard-analysis.yaml` | GitHub Actions workflow triggered on PRs |
| `scripts/mcpguard-analyze.sh` | Helper script for the Actions workflow |

### Modified Files
| File | Change |
|------|--------|
| `config/config.go` | Added `GitHubIntegrationConfig` struct |
| `config/default.yaml` | Added `github_integration` section (disabled) |
| `config/prod.yaml` | Added `github_integration` section (enabled) |
| `cmd/api/setup/resources.go` | Wire `prCommentService`, pass to `NewGitWebhookService` |
| `internal/model/http/git_webhook_request.go` | Added `GitHubPullRequestPayload` DTO for PR events |
| `internal/model/repositories/analysis_entity.go` | Added `PRNumber`, `RepoFullName` fields |
| `internal/controller/git_webhook_controller.go` | Route `X-GitHub-Event` header: `push` vs `pull_request` |
| `internal/controller/git_webhook_controller_test.go` | Updated mock with `RequestAnalysisWithPR` method |
| `internal/service/git_webhook_service.go` | `RequestAnalysisWithPR` method + PR comment posting after analysis |

---

## Phase 7: Multi-Language Rule Expansion (JavaScript/TypeScript)

**Task Spec**: [`docs/tasks/task-7.1-js-ts-rules.md`](../docs/tasks/task-7.1-js-ts-rules.md)

### New Files — Parser & Infrastructure
| File | Purpose |
|------|---------|
| `internal/service/static_analysis/languages/javascript/parser.go` | JS/TS AST parser using `go-tree-sitter` JavaScript grammar |

### New Files — Rules (11 rules, full parity with Python)
| File | Rule ID | Detects |
|------|---------|---------|
| `.../javascript/rules/javascript_rule_command_injection.go` | `MCP-JS-CMD-001` | `exec`, `execSync`, `eval`, `new Function`, `require('child_process')` |
| `.../javascript/rules/javascript_rule_file_operations.go` | `MCP-JS-FS-001` | `fs.*` sync/async operations, sensitive paths, path traversal |
| `.../javascript/rules/javascript_rule_tool_poisoning.go` | `MCP-JS-TP-001` | `server.tool()` dynamic args, description overwrite, `__proto__` pollution, `Object.assign` |
| `.../javascript/rules/javascript_rule_credential_theft.go` | `MCP-JS-CRED-001` | Sensitive file access, `process.env` secrets, `fetch`/`axios` exfiltration |
| `.../javascript/rules/javascript_rule_context_poisoning.go` | `MCP-JS-CTX-001` | `globalThis`/`window`/`global` modification, `Object.defineProperty`, `Reflect.set` |
| `.../javascript/rules/javascript_rule_indirect_injection.go` | `MCP-JS-ITI-001` | HTML parsers, hidden content, npm lifecycle hooks, return attacks, deserialization |
| `.../javascript/rules/javascript_rule_privilege_escalation.go` | `MCP-JS-PE-001` | `process.setuid`, FFI/native addons, Docker socket, container escape, `vm.*` |
| `.../javascript/rules/javascript_rule_remote_attacks.go` | `MCP-JS-REM-001` | `net.createServer`, reverse shells, `eval`, `curl\|node`, obfuscation |
| `.../javascript/rules/javascript_rule_llm_attacks.go` | `MCP-JS-LLM-001` | Jailbreak, prompt leakage, hallucination, backdoor, goal hijack, SQL injection |
| `.../javascript/rules/javascript_rule_malicious_user.go` | `MCP-JS-MUA-001` | Tool registration abuse, data injection, token theft, code leakage, installer spoofing |
| `.../javascript/rules/javascript_rule_multi_tool_attack.go` | `MCP-JS-MTA-001` | Shadowing, coverage attacks, obfuscation, forced execution, coordination, infectious attacks |

### New Files — Tests (1 per rule)
| File |
|------|
| `.../javascript/rules/javascript_rule_command_injection_test.go` |
| `.../javascript/rules/javascript_rule_file_operations_test.go` |
| `.../javascript/rules/javascript_rule_tool_poisoning_test.go` |
| `.../javascript/rules/javascript_rule_credential_theft_test.go` |
| `.../javascript/rules/javascript_rule_context_poisoning_test.go` |
| `.../javascript/rules/javascript_rule_indirect_injection_test.go` |
| `.../javascript/rules/javascript_rule_privilege_escalation_test.go` |
| `.../javascript/rules/javascript_rule_remote_attacks_test.go` |
| `.../javascript/rules/javascript_rule_llm_attacks_test.go` |
| `.../javascript/rules/javascript_rule_malicious_user_test.go` |
| `.../javascript/rules/javascript_rule_multi_tool_attack_test.go` |

### New Files — Test Fixtures
| File | Purpose |
|------|---------|
| `resources/test/test_command_injection.js` | JS fixture with vulnerable + safe command execution patterns |
| `resources/test/test_file_operations.js` | JS fixture with vulnerable + safe file system patterns |
| `resources/test/test_tool_poisoning.js` | JS fixture with vulnerable + safe tool registration patterns |

### Modified Files
| File | Change |
|------|--------|
| `internal/service/static_analysis/rule_registry.go` | Added `LanguageJavaScript = "javascript"` constant |
| `internal/service/static_analysis/engine.go` | Added JS parser dispatch in `parseAST` switch |
| `internal/utils/file_utils.go` | Added `.js`, `.ts`, `.jsx`, `.tsx` to `isSupportedExt` and `NormalizeExtension` |
| `cmd/api/setup/resources.go` | Added blank import `_ ".../javascript/rules"` for `init()` registration |

---

## Cross-Cutting Modified Files

| File | Phases |
|------|--------|
| `cmd/api/main.go` | 4 |
| `cmd/api/setup/resources.go` | 4, 6, 7 |
| `cmd/api/setup/routes.go` | 4, 5 |
| `config/config.go` | 4, 6 |
| `config/default.yaml` | 4, 6 |
| `config/prod.yaml` | 4, 6 |
| `docker-compose.yaml` | 4, 5 |
| `internal/service/git_webhook_service.go` | 4, 5, 6 |
| `go.mod` / `go.sum` | 4, 5 |
| `docs/tasks/tasks_status.json` | All (status tracking) |

---

## Totals

| Metric | Count |
|--------|-------|
| **New files** | 44 |
| **Modified files** | 18 |
| **JS security rules** | 11 (full parity with Python) |
| **Test files added** | 14 |
