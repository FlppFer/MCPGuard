# MCPGuard — API Flows, Expected Outcomes, and Error Paths

> **Version**: 1.0
> **Date**: April 2026
> **Purpose**: Scientific article reference — documents every API flow with happy paths, sad paths, status transitions, request/response schemas, and error codes.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Analysis Status State Machine](#2-analysis-status-state-machine)
3. [Authentication Flows](#3-authentication-flows)
4. [Flow 1 — Manual Analysis Request](#4-flow-1--manual-analysis-request)
5. [Flow 2 — GitHub Push Webhook](#5-flow-2--github-push-webhook)
6. [Flow 3 — GitHub Pull Request Webhook](#6-flow-3--github-pull-request-webhook)
7. [Flow 4 — Query Analysis Status](#7-flow-4--query-analysis-status)
8. [Flow 5 — Retrieve Static Analysis Result](#8-flow-5--retrieve-static-analysis-result)
9. [Flow 6 — Retrieve Merged Result (Static + Agentic)](#9-flow-6--retrieve-merged-result-static--agentic)
10. [Flow 7 — Agentic Analysis Callback (Python Worker → Go API)](#10-flow-7--agentic-analysis-callback-python-worker--go-api)
11. [Flow 8 — Retrieve Agentic Analysis Result](#11-flow-8--retrieve-agentic-analysis-result)
12. [Flow 9 — Queue-Based Async Worker Pipeline](#12-flow-9--queue-based-async-worker-pipeline)
13. [Flow 10 — GitHub PR Comment Integration](#13-flow-10--github-pr-comment-integration)
14. [Static Analysis Rule Catalog](#14-static-analysis-rule-catalog)
15. [Error Code Reference](#15-error-code-reference)
16. [HTTP Status Code Summary](#16-http-status-code-summary)

---

## 1. System Overview

MCPGuard is a security analysis platform for **Model Context Protocol (MCP)** tool implementations. It combines:

- **Static analysis** — AST-based rule engine detecting known vulnerability patterns in Python and JavaScript/TypeScript
- **Agentic analysis** — LLM-powered semantic analysis for threats invisible to static rules
- **GitHub integration** — Webhook-driven analysis on push/PR events with automated PR comments

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MCPGuard System                                │
│                                                                             │
│   ┌───────────┐     ┌─────────────┐     ┌──────────────┐                   │
│   │  GitHub    │────►│  Go API     │────►│ RabbitMQ     │                   │
│   │  Webhook   │     │  :8080      │     │ (optional)   │                   │
│   └───────────┘     │             │     └──────┬───────┘                   │
│                      │ Static      │            │                           │
│   ┌───────────┐     │ Analysis    │     ┌──────▼───────┐                   │
│   │  API       │────►│ Engine      │     │  Go Worker   │                   │
│   │  Client    │     │             │     │  (async)     │                   │
│   └───────────┘     └──────┬──────┘     └──────────────┘                   │
│                            │                                                │
│                     ┌──────▼──────┐     ┌──────────────┐                   │
│                     │  S3 / Local │     │ Python Worker│                   │
│                     │  Storage    │     │ (agentic)    │                   │
│                     └─────────────┘     └──────────────┘                   │
│                                                                             │
│                     ┌─────────────┐     ┌──────────────┐                   │
│                     │  SQLite DB  │     │ Prometheus + │                   │
│                     │  (status)   │     │ Grafana      │                   │
│                     └─────────────┘     └──────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Analysis Status State Machine

Every analysis follows a deterministic state machine. Each state is persisted in the database.

```
                    ┌──────────┐
                    │ created  │
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              ▼                     ▼
       ┌────────────┐       ┌────────────────┐
       │  queued     │       │ downloading_   │  (local mode)
       │  (queue     │       │ repo           │
       │   mode)     │       └───────┬────────┘
       └──────┬─────┘               │
              │                     ▼
              │              ┌────────────────┐
              │              │ uploading_     │
              │              │ source         │
              │              └───────┬────────┘
              │                     │
              ▼                     ▼
       ┌────────────┐       ┌────────────────┐
       │ downloading│       │ parsing_files  │
       │ _repo      │       └───────┬────────┘
       │ (worker)   │               │
       └──────┬─────┘               ▼
              │              ┌────────────────────┐
              ▼              │ static_analysis_    │
       ┌────────────┐       │ running             │
       │ parsing_   │       └───────┬─────────────┘
       │ files      │               │
       └──────┬─────┘               ▼
              │              ┌────────────────────┐
              ▼              │ static_analysis_    │
       ┌────────────────┐    │ done                │◄──── Result available
       │ static_analysis│    └───────┬─────────────┘
       │ _running       │            │
       └──────┬─────────┘            │ (agentic enabled?)
              │                     │
              ▼               ┌─────┴─────┐
       ┌────────────────┐     │           │
       │ static_analysis│     ▼    No     ▼  Yes
       │ _done          │  (done)  ┌──────────────────┐
       └──────┬─────────┘         │ waiting_agent_    │
              │                   │ analysis          │
              │                   └──────┬────────────┘
              │                          │
              │                          ▼
              │                   ┌──────────────────┐
              │                   │ agent_analysis_   │
              │                   │ running           │
              │                   └──────┬────────────┘
              │                          │
              │                          ▼
              │                   ┌──────────────────┐
              │                   │ agent_analysis_   │
              │                   │ done              │
              │                   └──────┬────────────┘
              │                          │
              └───────────┬──────────────┘
                          ▼
                   ┌─────────────┐
                   │  completed  │
                   └─────────────┘

  Any state ──────► ┌──────────┐
                    │  failed  │
                    └──────────┘
```

### Status Table

| Status | Code | Description |
|--------|------|-------------|
| `created` | 0 | Analysis entity created in DB |
| `queued` | 1 | Published to RabbitMQ queue |
| `downloading_repo` | 2 | Git clone in progress |
| `uploading_source` | 3 | ZIP uploaded to S3 |
| `parsing_files` | 4 | Source files being parsed into ASTs |
| `static_analysis_running` | 5 | Static rules executing |
| `static_analysis_done` | 6 | Static analysis complete — results available |
| `waiting_agent_analysis` | 7 | Job submitted to Python agentic worker |
| `agent_analysis_running` | 8 | LLM-based analysis in progress |
| `agent_analysis_done` | 9 | Agentic analysis result received |
| `completed` | 10 | All analyses finished |
| `failed` | 11 | Error at any stage — see `error_message` |

---

## 3. Authentication Flows

### 3.1 API Key Authentication

**Applies to**: All `/v1/*` endpoints except `/v1/webhook/github`

```
Client                                    Go API
  │                                         │
  │  GET /v1/analysis/{id}/status           │
  │  X-API-Key: sk-my-key                   │
  │  X-Client-ID: my-client                 │
  │────────────────────────────────────────►│
  │                                         │
  │  [Middleware: lookup my-client in map]   │
  │  [Compare sk-my-key with constant-time] │
  │                                         │
  │◄──── 200 OK (auth passed) ─────────────│
  │  OR                                     │
  │◄──── 401 Unauthorized ─────────────────│
```

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| **Happy**: Valid `X-API-Key` + `X-Client-ID` | Pass-through to handler | — |
| **Sad**: Missing both headers | `401` | `{"error":"missing_headers","message":"Missing required headers: X-API-Key, X-Client-ID"}` |
| **Sad**: Missing `X-API-Key` only | `401` | `{"error":"missing_header","message":"Missing required header: X-API-Key"}` |
| **Sad**: Missing `X-Client-ID` only | `401` | `{"error":"missing_header","message":"Missing required header: X-Client-ID"}` |
| **Sad**: Unknown client ID | `401` | `{"error":"invalid_credentials","message":"Invalid API key or client ID"}` |
| **Sad**: Wrong API key for client | `401` | `{"error":"invalid_credentials","message":"Invalid API key or client ID"}` |

> Keys are compared using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

### 3.2 Webhook Signature Authentication

**Applies to**: `POST /v1/webhook/github`

```
GitHub                                    Go API
  │                                         │
  │  POST /v1/webhook/github                │
  │  X-Hub-Signature-256: sha256=abc123...  │
  │  X-GitHub-Event: push                   │
  │  X-GitHub-Delivery: uuid                │
  │  Body: { ... payload ... }              │
  │────────────────────────────────────────►│
  │                                         │
  │  [Read body, compute HMAC-SHA256]       │
  │  [Compare with X-Hub-Signature-256]     │
  │                                         │
  │◄──── 202 Accepted ─────────────────────│
```

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| **Happy**: Valid HMAC signature | Pass-through | — |
| **Sad**: Missing `X-Hub-Signature-256` | `401` | `{"error":"missing_signature","message":"X-Hub-Signature-256 header is required"}` |
| **Sad**: Invalid signature | `401` | `{"error":"invalid_signature","message":"Invalid webhook signature"}` |
| **Sad**: Body read failure | `400` | `{"error":"read_error","message":"Failed to read request body"}` |

---

## 4. Flow 1 — Manual Analysis Request

**Endpoint**: `POST /v1/analysis`
**Auth**: API Key
**Purpose**: Manually trigger a security analysis for any Git repository.

### Sequence Diagram

```
Client                  Go API                  Git          S3         Static Engine    Python Worker
  │                       │                      │            │              │                 │
  │  POST /v1/analysis    │                      │            │              │                 │
  │  { repo_url, branch } │                      │            │              │                 │
  │──────────────────────►│                      │            │              │                 │
  │                       │                      │            │              │                 │
  │                       │  git clone           │            │              │                 │
  │                       │─────────────────────►│            │              │                 │
  │                       │◄─────────────────────│            │              │                 │
  │                       │                      │            │              │                 │
  │                       │  Upload ZIP                       │              │                 │
  │                       │──────────────────────────────────►│              │                 │
  │                       │                      │            │              │                 │
  │  202 Accepted         │                      │            │              │                 │
  │  { analysis_id }      │                      │            │              │                 │
  │◄──────────────────────│                      │            │              │                 │
  │                       │                      │            │              │                 │
  │                       │  [async goroutine]   │            │              │                 │
  │                       │  Parse files ────────────────────────────────────►│                 │
  │                       │  Run rules   ────────────────────────────────────►│                 │
  │                       │◄─────────────────────────────────────────────────│                 │
  │                       │                      │            │              │                 │
  │                       │  Upload static result             │              │                 │
  │                       │──────────────────────────────────►│              │                 │
  │                       │                      │            │              │                 │
  │                       │  POST /analyze (if agentic enabled)              │                 │
  │                       │─────────────────────────────────────────────────────────────────►  │
  │                       │◄────────────────────────────────────────────────────────────────  │
```

### Request

```http
POST /v1/analysis HTTP/1.1
Content-Type: application/json
X-API-Key: dev-key
X-Client-ID: dev-client

{
  "repo_url": "https://github.com/owner/repo.git",
  "branch": "main",
  "commit": "abc123def456"
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `repo_url` | `string` | **Yes** | — | Git clone URL |
| `branch` | `string` | No | `"main"` | Branch to analyze |
| `commit` | `string` | No | `""` | Specific commit SHA |

### Happy Path

| Step | Status Transition | Action |
|------|-------------------|--------|
| 1 | → `created` | Entity created in DB |
| 2 | → `downloading_repo` | `git clone` of the repository |
| 3 | — | ZIP archive created and uploaded to S3 (`{id}.zip`) |
| 4 | → `static_analysis_running` | Files parsed to ASTs, rules executed |
| 5 | → `static_analysis_done` | Results serialized and uploaded to S3 (`analysis-results/{id}_static.json`) |
| 6 | → `waiting_agent_analysis` | (if agentic enabled) Job submitted to Python worker |
| 7 | → `completed` | (after agentic callback) All results available |

**Response** (Step 1 — immediate):
```json
HTTP/1.1 202 Accepted

{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "created",
  "message": "Analysis started successfully",
  "timestamp": "2026-04-11T20:00:00Z"
}
```

### Sad Paths

| Scenario | HTTP Status | Error Code | Response |
|----------|-------------|------------|----------|
| Missing `repo_url` | `400` | `missing_field` | `{"error":"missing_field","message":"repo_url is required"}` |
| Malformed JSON body | `400` | `invalid_request` | `{"error":"invalid_request","message":"Failed to parse request body"}` |
| Git clone fails (invalid URL, private repo, network) | `500` | `analysis_failed` | `{"error":"analysis_failed","message":"<git error details>"}` |
| S3 upload fails | `500` | `analysis_failed` | `{"error":"analysis_failed","message":"<storage error>"}` |
| Queue publish fails (queue mode) | `500` | `analysis_failed` | Status → `failed`, `error_message` set |
| Static analysis engine error (async) | — | — | Status → `failed`, `error_message` set |
| Agentic worker unreachable (async) | — | — | Falls back to `static_analysis_done` (non-fatal) |

---

## 5. Flow 2 — GitHub Push Webhook

**Endpoint**: `POST /v1/webhook/github`
**Auth**: Webhook HMAC Signature
**Trigger**: GitHub push event (code pushed to a branch)

### Request

```http
POST /v1/webhook/github HTTP/1.1
Content-Type: application/json
X-Hub-Signature-256: sha256=abc123...
X-GitHub-Event: push
X-GitHub-Delivery: 72d3162e-cc78-11e3-81ab-4c9367dc0958

{
  "ref": "refs/heads/main",
  "after": "abc123def456",
  "repository": {
    "full_name": "owner/repo",
    "clone_url": "https://github.com/owner/repo.git"
  }
}
```

### Happy Path

Same pipeline as Flow 1 after payload extraction. Branch extracted from `ref`, commit from `after`, URL from `repository.clone_url`.

**Response**:
```json
HTTP/1.1 202 Accepted

{
  "analysis_id": "...",
  "status": "created",
  "message": "Analysis started successfully",
  "timestamp": "..."
}
```

### Sad Paths

| Scenario | HTTP Status | Error Code |
|----------|-------------|------------|
| Invalid HMAC signature | `401` | `invalid_signature` |
| Malformed JSON payload | `400` | `invalid_payload` |
| Missing `repository.clone_url` | `400` | `missing_field` |
| Clone/analysis failure | `500` | `analysis_failed` |

---

## 6. Flow 3 — GitHub Pull Request Webhook

**Endpoint**: `POST /v1/webhook/github`
**Auth**: Webhook HMAC Signature
**Trigger**: GitHub `pull_request` event (opened, synchronize, reopened)

### Request

```http
POST /v1/webhook/github HTTP/1.1
X-Hub-Signature-256: sha256=...
X-GitHub-Event: pull_request

{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "head": {
      "ref": "feature/new-tool",
      "sha": "def789..."
    }
  },
  "repository": {
    "full_name": "owner/repo",
    "clone_url": "https://github.com/owner/repo.git"
  }
}
```

### Happy Path

Same as Flow 1, with additional steps:
1. Analysis entity stores `pr_number` and `repo_full_name`
2. After static analysis completes, findings are **posted as a PR comment** (if GitHub integration enabled)
3. Comment formatted as Markdown with findings table, severity badges, and summary

**Response**: Same `202 Accepted` with `analysis_id`.

### Sad Paths

| Scenario | HTTP Status | Error Code |
|----------|-------------|------------|
| Unsupported action (`closed`, `edited`, etc.) | `200` | — (ignored) |
| Missing `repository.clone_url` | `400` | `missing_field` |
| PR comment posting fails | — | Non-fatal warning (analysis still completes) |

### Handled PR Actions

| Action | Behavior |
|--------|----------|
| `opened` | ✅ Triggers analysis |
| `synchronize` | ✅ Triggers analysis (new commits pushed) |
| `reopened` | ✅ Triggers analysis |
| Any other | ⏭️ Ignored with `200 OK {"status":"ignored"}` |

### Unhandled Event Types

| Event | Behavior |
|-------|----------|
| `push` | Routed to push handler |
| `pull_request` | Routed to PR handler |
| Any other (`issues`, `release`, etc.) | `200 OK {"status":"ignored","message":"Event type 'X' not handled"}` |

---

## 7. Flow 4 — Query Analysis Status

**Endpoint**: `GET /v1/analysis/{id}/status`
**Auth**: API Key

### Request

```http
GET /v1/analysis/550e8400-e29b-41d4-a716-446655440000/status HTTP/1.1
X-API-Key: dev-key
X-Client-ID: dev-client
```

### Happy Path

**Response**:
```json
HTTP/1.1 200 OK

{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "repo_url": "https://github.com/owner/repo.git",
  "branch": "main",
  "commit": "abc123",
  "status": "static_analysis_done",
  "error_message": "",
  "created_at": "2026-04-11T20:00:00Z",
  "updated_at": "2026-04-11T20:00:15Z"
}
```

### Sad Paths

| Scenario | HTTP Status | Error Code | Response |
|----------|-------------|------------|----------|
| Missing `{id}` parameter | `400` | `missing_id` | `{"error":"missing_id","message":"Analysis ID is required"}` |
| Analysis ID not found | `404` | `not_found` | `{"error":"not_found","message":"analysis not found: ..."}` |
| DB read error | `500` | `internal_error` | `{"error":"internal_error","message":"..."}` |

---

## 8. Flow 5 — Retrieve Static Analysis Result

**Endpoint**: `GET /v1/analysis/{id}/result`
**Auth**: API Key
**Precondition**: Analysis status must be `static_analysis_done` or `completed`

### Happy Path

**Response**:
```json
HTTP/1.1 200 OK

{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "files_analyzed": 23,
  "findings": [
    {
      "rule_id": "MCP-JS-CMD-001",
      "message": "Dangerous exec() call detected — possible command injection",
      "file_path": "src/tools/runner.js",
      "line": 42,
      "severity": "critical",
      "snippet": "exec(userInput)"
    },
    {
      "rule_id": "MCP-DTI-001-TOOL-POISON",
      "message": "Tool description override detected",
      "file_path": "src/server.py",
      "line": 15,
      "severity": "high",
      "snippet": "tool.description = user_input"
    }
  ]
}
```

### Sad Paths

| Scenario | HTTP Status | Error Code | Response |
|----------|-------------|------------|----------|
| Missing `{id}` | `400` | `missing_id` | `{"error":"missing_id","message":"Analysis ID is required"}` |
| ID not found | `404` | `not_found` | `{"error":"not_found","message":"analysis not found: ..."}` |
| Analysis still running | `202` | `analysis_pending` | `{"error":"analysis_pending","message":"analysis not complete, current status: static_analysis_running"}` |
| S3 download failure | `500` | `internal_error` | `{"error":"internal_error","message":"failed to download result: ..."}` |

> **Note**: Status `202 Accepted` (not `200`) indicates the analysis is in progress and the client should poll again.

---

## 9. Flow 6 — Retrieve Merged Result (Static + Agentic)

**Endpoint**: `GET /v1/analysis/{id}/result/full`
**Auth**: API Key
**Precondition**: Analysis status must be `static_analysis_done` or `completed`

### Happy Path

**Response**:
```json
HTTP/1.1 200 OK

{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "static_result": {
    "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
    "files_analyzed": 23,
    "findings": [
      {
        "rule_id": "MCP-JS-CMD-001",
        "message": "Dangerous exec() call detected",
        "file_path": "src/tools/runner.js",
        "line": 42,
        "severity": "critical",
        "snippet": "exec(userInput)"
      }
    ]
  },
  "agentic_result": {
    "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
    "findings": [
      {
        "category": "tool_poisoning",
        "description": "Tool description contains hidden instruction to redirect API calls",
        "file_path": "src/tools/data_fetcher.py",
        "start_line": 15,
        "end_line": 22,
        "severity": "critical",
        "confidence": 0.92,
        "suggestion": "Remove hidden instructions from tool description."
      }
    ],
    "summary": "Found 1 critical tool poisoning issue.",
    "model_used": "gpt-4",
    "timestamp": "2026-04-11T20:01:00Z"
  }
}
```

### Partial Results

If agentic analysis hasn't completed yet but static analysis is done:
- `status`: `"static_analysis_done"`
- `static_result`: populated
- `agentic_result`: `null`

This allows clients to view static findings immediately without waiting for the LLM.

### Sad Paths

Same as Flow 5: `400` (missing ID), `404` (not found), `202` (still running), `500` (storage error).

---

## 10. Flow 7 — Agentic Analysis Callback (Python Worker → Go API)

**Endpoint**: `POST /v1/agentic_analysis`
**Auth**: API Key
**Direction**: Python Worker → Go API (callback after LLM analysis completes)

### Sequence Diagram

```
Python Worker                    Go API                    S3
  │                                │                        │
  │  POST /v1/agentic_analysis     │                        │
  │  { analysis_id, findings, ... }│                        │
  │───────────────────────────────►│                        │
  │                                │                        │
  │                                │  Upload to S3          │
  │                                │  (agentic result)      │
  │                                │───────────────────────►│
  │                                │                        │
  │                                │  Update DB status      │
  │                                │  → completed           │
  │                                │                        │
  │  200 OK {"status":"received"}  │                        │
  │◄───────────────────────────────│                        │
```

### Request

```json
POST /v1/agentic_analysis HTTP/1.1
Content-Type: application/json
X-API-Key: worker-key
X-Client-ID: python-worker

{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "findings": [
    {
      "category": "data_exfiltration",
      "description": "Return value contains hidden base64-encoded user data",
      "file_path": "src/tools/fetcher.js",
      "start_line": 30,
      "end_line": 35,
      "severity": "high",
      "confidence": 0.88,
      "suggestion": "Sanitize tool return values before sending to client."
    }
  ],
  "summary": "Found 1 high-severity data exfiltration pattern.",
  "model_used": "gpt-4",
  "timestamp": "2026-04-11T20:01:30Z"
}
```

### Happy Path

1. Result JSON uploaded to S3: `analysis-results/{id}_agentic.json`
2. Analysis entity status updated: → `completed`
3. Response: `200 OK {"status":"received"}`

### Sad Paths

| Scenario | HTTP Status | Error Code | Response |
|----------|-------------|------------|----------|
| Missing `analysis_id` | `400` | `missing_field` | `{"error":"missing_field","message":"analysis_id is required"}` |
| Malformed JSON | `400` | `invalid_request` | `{"error":"invalid_request","message":"Failed to parse request body"}` |
| Analysis ID not in DB | `404` | `not_found` | `{"error":"not_found","message":"analysis not found: ..."}` |
| S3 upload failure | `500` | `processing_failed` | `{"error":"processing_failed","message":"failed to upload agentic result: ..."}` |
| DB update failure | `500` | `processing_failed` | `{"error":"processing_failed","message":"failed to update analysis status: ..."}` |

---

## 11. Flow 8 — Retrieve Agentic Analysis Result

**Endpoint**: `GET /v1/agentic_analysis/{id}/result`
**Auth**: API Key
**Precondition**: Analysis status must be `completed` or `agent_analysis_done`

### Happy Path

**Response**: Raw agentic result JSON (same structure as the callback body).

### Sad Paths

| Scenario | HTTP Status | Error Code |
|----------|-------------|------------|
| Missing `{id}` | `400` | `missing_id` |
| ID not found | `404` | `not_found` |
| Agentic analysis not complete | `202` | `analysis_pending` |
| S3 download failure | `500` | `internal_error` |

---

## 12. Flow 9 — Queue-Based Async Worker Pipeline

**Mode**: Enabled when `messaging.enabled: true` in config
**Transport**: RabbitMQ (`amqp://`)
**Queue**: `static_analysis_jobs`

### Sequence Diagram

```
Go API                RabbitMQ            Go Worker             S3
  │                      │                    │                  │
  │  Publish job         │                    │                  │
  │  { analysis_id,      │                    │                  │
  │    source_key, ... } │                    │                  │
  │─────────────────────►│                    │                  │
  │                      │                    │                  │
  │  Status → queued     │  Deliver message   │                  │
  │                      │───────────────────►│                  │
  │                      │                    │                  │
  │                      │                    │  Download ZIP    │
  │                      │                    │─────────────────►│
  │                      │                    │◄─────────────────│
  │                      │                    │                  │
  │                      │                    │  Extract + Parse │
  │                      │                    │  Run analysis    │
  │                      │                    │                  │
  │                      │                    │  Upload results  │
  │                      │                    │─────────────────►│
  │                      │                    │                  │
  │                      │                    │  ACK message     │
  │                      │◄───────────────────│                  │
  │                      │                    │                  │
  │                      │                    │  Submit agentic  │
  │                      │                    │  (if enabled)    │
```

### Worker Job Message

```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "repo_url": "https://github.com/owner/repo.git",
  "branch": "main",
  "commit": "abc123",
  "source_key": "550e8400-e29b-41d4-a716-446655440000.zip"
}
```

### Worker Processing Steps

| Step | Status Transition | Action |
|------|-------------------|--------|
| 1 | → `downloading_repo` | Download ZIP from S3 |
| 2 | → `parsing_files` | Extract ZIP, parse source files to ASTs |
| 3 | → `static_analysis_running` | Execute all registered rules |
| 4 | — | Upload results to S3 |
| 5 | → `static_analysis_done` | ACK the RabbitMQ message |
| 6 | → `waiting_agent_analysis` | (if agentic enabled) Submit to Python worker |

### Error Handling

| Scenario | Behavior |
|----------|----------|
| Malformed message | NACK (discard, do not requeue) |
| Processing failure (clone, parse, analysis) | NACK (requeue for retry) |
| S3 upload failure | NACK (requeue), status → `failed` |
| Agentic submission failure | Non-fatal, status stays at `static_analysis_done` |
| Worker crash | Message redelivered (auto-ack disabled) |

### Fair Dispatch

QoS is set to `prefetch=1` — each worker only processes one message at a time, enabling horizontal scaling with multiple worker instances.

---

## 13. Flow 10 — GitHub PR Comment Integration

**Trigger**: Automatic, after static analysis completes for a PR-triggered analysis
**Precondition**: `github_integration.enabled: true` + valid `GITHUB_TOKEN`

### Sequence Diagram

```
Go API                           GitHub API
  │                                  │
  │  [Static analysis done]          │
  │  [entity.PRNumber > 0]           │
  │                                  │
  │  POST /repos/{owner}/{repo}/     │
  │       issues/{pr}/comments       │
  │  Authorization: Bearer {token}   │
  │  Body: { "body": "## 🔍 ..." }  │
  │─────────────────────────────────►│
  │                                  │
  │◄──── 201 Created ───────────────│
```

### Comment Format

The PR comment is formatted as Markdown containing:
- Header with MCPGuard branding
- Summary: total findings count by severity
- Findings table: rule ID, file path, line, severity, message
- Footer with analysis metadata

### Error Handling

| Scenario | Behavior |
|----------|----------|
| GitHub token invalid/expired | Logged as warning, analysis still completes |
| GitHub API rate limit | Logged as warning, analysis still completes |
| Network failure | Logged as warning, analysis still completes |

> PR comment posting is **non-blocking and non-fatal** — it never causes an analysis to fail.

---

## 14. Static Analysis Rule Catalog

### Python Rules (11 rules)

| Rule ID | Name | Severity | Detects |
|---------|------|----------|---------|
| `MCP-DTI-002` | Command Injection | Critical | `os.system`, `subprocess`, `eval`, `exec` |
| `MCP-DTI-002-FILE-OPS` | File Operations | High | `open()`, `os.remove`, path traversal, sensitive paths |
| `MCP-DTI-001-TOOL-POISON` | Tool Poisoning | Critical | Dynamic tool descriptions, hidden instructions |
| `MCP-DTI-003` | Credential Theft | High | Sensitive file access, env var secrets, exfiltration |
| `MCP-CTX-001` | Context Poisoning | High | Global state modification, context manipulation |
| `MCP-ITI-001` | Indirect Injection | High | HTML parsers, hidden content, deserialization |
| `MCP-MUA-001` | Privilege Escalation | Critical | `setuid`, FFI, container escape, `ctypes` |
| `MCP-DTI-003-REMOTE` | Remote Attacks | Critical | Socket servers, reverse shells, obfuscation |
| `MCP-LLM-001` | LLM Attacks | High | Jailbreak, prompt leakage, hallucination vectors |
| `MCP-MUA-002-USER` | Malicious User | Medium | Tool registration abuse, data injection |
| `MCP-MTA-001` | Multi-Tool Attack | High | Tool shadowing, coordination, infectious attacks |

### JavaScript/TypeScript Rules (11 rules — full parity)

| Rule ID | Name | Severity | Detects |
|---------|------|----------|---------|
| `MCP-JS-CMD-001` | Command Injection | Critical | `exec`, `execSync`, `eval`, `new Function`, `child_process` |
| `MCP-JS-FS-001` | File Operations | High | `fs.*` sync/async, path traversal, sensitive paths |
| `MCP-JS-TP-001` | Tool Poisoning | Critical | `server.tool()` dynamic args, `__proto__` pollution, `Object.assign` |
| `MCP-JS-CRED-001` | Credential Theft | High | Sensitive file access, `process.env` secrets, `fetch`/`axios` exfiltration |
| `MCP-JS-CTX-001` | Context Poisoning | High | `globalThis`/`window`/`global` modification, `Object.defineProperty` |
| `MCP-JS-ITI-001` | Indirect Injection | High | HTML parsers, hidden content, npm lifecycle hooks, deserialization |
| `MCP-JS-PE-001` | Privilege Escalation | Critical | `process.setuid`, FFI/native addons, Docker socket, `vm.*` |
| `MCP-JS-REM-001` | Remote Attacks | Critical | `net.createServer`, reverse shells, `curl\|node`, obfuscation |
| `MCP-JS-LLM-001` | LLM Attacks | High | Jailbreak, prompt leakage, hallucination, backdoor, goal hijack |
| `MCP-JS-MUA-001` | Malicious User | Medium | Tool registration abuse, token theft, installer spoofing |
| `MCP-JS-MTA-001` | Multi-Tool Attack | High | Shadowing, coverage attacks, coordination, infectious attacks |

### Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Immediate exploitation risk — remote code execution, active data exfiltration |
| `high` | Significant security flaw — credential exposure, privilege escalation |
| `medium` | Potential risk requiring context — abuse patterns, suspicious registrations |
| `low` | Informational — weak patterns, best practice violations |
| `info` | Advisory — no direct security impact |

---

## 15. Error Code Reference

| Error Code | Meaning | Typical HTTP Status |
|------------|---------|---------------------|
| `invalid_request` | Malformed JSON body | `400` |
| `missing_field` | Required field absent (e.g., `repo_url`, `analysis_id`) | `400` |
| `missing_id` | URL path parameter `{id}` is empty | `400` |
| `invalid_payload` | GitHub webhook payload cannot be parsed | `400` |
| `not_found` | Analysis ID does not exist in database | `404` |
| `analysis_pending` | Results requested but analysis is still running | `202` |
| `analysis_failed` | Analysis pipeline error (clone, parse, rule engine) | `500` |
| `processing_failed` | Agentic result processing error (S3, DB update) | `500` |
| `internal_error` | Unexpected server-side error | `500` |
| `missing_signature` | Webhook missing `X-Hub-Signature-256` | `401` |
| `invalid_signature` | Webhook HMAC validation failed | `401` |
| `missing_headers` | API key auth headers missing | `401` |
| `missing_header` | Single auth header missing | `401` |
| `invalid_credentials` | API key or client ID invalid | `401` |

---

## 16. HTTP Status Code Summary

| Status Code | Usage |
|-------------|-------|
| `200 OK` | Successful data retrieval (status, results, agentic callback ack) |
| `202 Accepted` | Analysis started (async); or analysis pending (poll again) |
| `400 Bad Request` | Malformed input, missing fields |
| `401 Unauthorized` | Authentication failure (API key or webhook signature) |
| `404 Not Found` | Analysis ID not in database |
| `500 Internal Server Error` | Server-side processing failure |

---

## Appendix A: Complete Endpoint Map

| Method | Path | Auth | Description | Success | Key Errors |
|--------|------|------|-------------|---------|------------|
| `GET` | `/health` | None | Health check | `200` `{"status":"ok"}` | — |
| `GET` | `/metrics` | None | Prometheus metrics | `200` | — |
| `POST` | `/v1/webhook/github` | Webhook HMAC | GitHub webhook | `202` | `401`, `400` |
| `POST` | `/v1/analysis` | API Key | Start analysis | `202` | `400`, `500` |
| `GET` | `/v1/analysis/{id}/status` | API Key | Get status | `200` | `400`, `404` |
| `GET` | `/v1/analysis/{id}/result` | API Key | Get static result | `200` | `202`, `404`, `500` |
| `GET` | `/v1/analysis/{id}/result/full` | API Key | Get merged result | `200` | `202`, `404`, `500` |
| `POST` | `/v1/agentic_analysis` | API Key | Agentic callback | `200` | `400`, `404`, `500` |
| `GET` | `/v1/agentic_analysis/{id}/result` | API Key | Get agentic result | `200` | `202`, `404`, `500` |

---

## Appendix B: Storage Key Patterns

| Pattern | Content | Written By |
|---------|---------|------------|
| `{analysis_id}.zip` | Source archive | Go API (upload after clone) |
| `analysis-results/{analysis_id}_static.json` | Static analysis findings | Go API / Worker (after rule execution) |
| `analysis-results/{analysis_id}_agentic.json` | Agentic analysis findings | Go API (after receiving callback) |
