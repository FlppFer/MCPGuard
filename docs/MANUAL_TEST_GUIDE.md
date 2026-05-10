# MCPGuard — Manual API Test Guide

This guide walks through testing every API flow end-to-end with `curl`.
Results are documented inline after each test.

---

## Prerequisites

### 1. Configure `.env` file

Ensure `e:\dev\projetos\MCPGuard\.env` contains:

```env
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
MCPGUARD_API_KEYS=dev-client:dev-key
GITHUB_TOKEN=<your_github_pat>
```

### 2. Start Full Stack

```powershell
docker compose --profile observability up --build -d
```

Starts: MCPGuard API (8080), LocalStack (4566), Prometheus (9090), Grafana (3000), cAdvisor (8081), Node Exporter (9100).

### 3. Verify Health

```powershell
curl http://localhost:8080/health
```

Expected: `{"status":"ok"}`

### 4. Agentic Analysis Mode

- **Mock mode** (default, no Python worker needed): `config/default.yaml` → `agentic.mock: true`
- **Real mode** (requires Python worker on port 5000): set `agentic.mock: false` and `worker_url: "http://host.docker.internal:5000"`

---

## Variables Used Throughout

```powershell
$WEBHOOK_SECRET = "your-webhook-secret-here"
$REPO_URL = "https://github.com/FlppFer/vulnerable_mcp_server.git"

# HMAC helper — run once in your session
function Get-HmacSignature {
    param([string]$Body, [string]$Secret)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Secret)
    $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Body))
    return "sha256=" + (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}
```

---

## Test 1: Manual Analysis (POST /v1/analysis)

### 1A — Happy Path

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d '{"repo_url":"https://github.com/FlppFer/vulnerable_mcp_server.git","branch":"main"}'
```

**Expected:** HTTP 202, JSON with `analysis_id`, `status`.

```
📋 Result:
   HTTP Status: ___
   analysis_id: ___
   ✅ / ❌
```

### 1B — Missing repo_url

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d '{"branch":"main"}'
```

**Expected:** HTTP 400, `{"error":"missing_field"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

### 1C — Malformed JSON

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d '{not json}'
```

**Expected:** HTTP 400, `{"error":"invalid_request"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

### 1D — Missing Auth Headers

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" `
  -d '{"repo_url":"https://github.com/FlppFer/vulnerable_mcp_server.git"}'
```

**Expected:** HTTP 401

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

### 1E — Invalid API Key

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: wrong-key" `
  -H "X-Client-ID: dev-client" `
  -d '{"repo_url":"https://github.com/FlppFer/vulnerable_mcp_server.git"}'
```

**Expected:** HTTP 401

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 2: GitHub Push Webhook (POST /v1/webhook/github)

### 2A — Push Event Happy Path

```powershell
$pushPayload = '{"ref":"refs/heads/main","after":"","before":"000000","repository":{"clone_url":"https://github.com/FlppFer/vulnerable_mcp_server.git","full_name":"FlppFer/vulnerable_mcp_server","private":true},"head_commit":{"id":"","message":"test commit"}}'
$bodyBytes = [Text.Encoding]::UTF8.GetBytes($pushPayload)
[System.IO.File]::WriteAllBytes("$env:TEMP\push_payload.json", $bodyBytes)
$sig = Get-HmacSignature -Body $pushPayload -Secret $WEBHOOK_SECRET
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: $sig" `
  -H "X-GitHub-Event: push" `
  -H "X-GitHub-Delivery: test-delivery-001" `
  --data-binary "@$env:TEMP\push_payload.json"
```

**Expected:** HTTP 202, JSON with `analysis_id`, `status`.

> Note: `after` left empty so no specific commit checkout is attempted.

```
📋 Result:
   HTTP Status: 202 ✅
   analysis_id: 9b9b15e3-a492-4b72-ad82-f133eb453918
   ✅
```

### 2B — Missing Signature

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-GitHub-Event: push" `
  -d '{"ref":"refs/heads/main","repository":{"clone_url":"https://github.com/FlppFer/vulnerable_mcp_server.git"}}'
```

**Expected:** HTTP 401, `missing_signature`

```
📋 Result:
   HTTP Status: 401 ✅
   ✅
```

### 2C — Invalid Signature

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000000" `
  -H "X-GitHub-Event: push" `
  -d '{"ref":"refs/heads/main","repository":{"clone_url":"https://github.com/FlppFer/vulnerable_mcp_server.git"}}'
```

**Expected:** HTTP 401, `invalid_signature`

```
📋 Result:
   HTTP Status: 401 ✅
   ✅
```

### 2D — Unknown Event Type

```powershell
$body = '{"action":"test"}'
$sig = Get-HmacSignature -Body $body -Secret $WEBHOOK_SECRET
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: $sig" `
  -H "X-GitHub-Event: issues" `
  -d $body
```

**Expected:** HTTP 200, `{"status":"ignored"}`

```
📋 Result:
   HTTP Status: 200 ✅
   ✅
```

---

## Test 3: PR Webhook (POST /v1/webhook/github with pull_request)

### 3A — PR Opened

```powershell
$prPayload = '{"action":"opened","number":42,"pull_request":{"head":{"ref":"main","sha":""}},"repository":{"clone_url":"https://github.com/FlppFer/vulnerable_mcp_server.git","full_name":"FlppFer/vulnerable_mcp_server"}}'
$bodyBytes = [Text.Encoding]::UTF8.GetBytes($prPayload)
[System.IO.File]::WriteAllBytes("$env:TEMP\pr_payload.json", $bodyBytes)
$sig = Get-HmacSignature -Body $prPayload -Secret $WEBHOOK_SECRET
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: $sig" `
  -H "X-GitHub-Event: pull_request" `
  -H "X-GitHub-Delivery: test-delivery-002" `
  --data-binary "@$env:TEMP\pr_payload.json"
```

**Expected:** HTTP 202, JSON with `analysis_id`.

```
📋 Result:
   HTTP Status: ___
   analysis_id: ___
   ✅ / ❌
```

### 3B — PR Closed (Ignored)

```powershell
$body = '{"action":"closed","number":42,"pull_request":{"head":{"ref":"main","sha":"abc"}},"repository":{"clone_url":"https://github.com/FlppFer/vulnerable_mcp_server.git","full_name":"FlppFer/vulnerable_mcp_server"}}'
$sig = Get-HmacSignature -Body $body -Secret $WEBHOOK_SECRET
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: $sig" `
  -H "X-GitHub-Event: pull_request" `
  -d $body
```

**Expected:** HTTP 200, `{"status":"ignored","action":"closed"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 4: Query Analysis Status (GET /v1/analysis/{id}/status)

### 4A — Valid ID

```powershell
$ANALYSIS_ID = "PASTE_ID_HERE"
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/analysis/$ANALYSIS_ID/status `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 200, JSON with `status`, `repo_url`, timestamps.

```
📋 Result:
   HTTP Status: 200 ✅
   status: completed ✅
   ✅
```

### 4B — Non-Existent ID

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/analysis/does-not-exist/status `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 404, `{"error":"not_found"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 5: Get Static Result (GET /v1/analysis/{id}/result)

### 5A — Completed Analysis

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/analysis/$ANALYSIS_ID/result `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 200, JSON with `findings` array.

```
📋 Result:
   HTTP Status: 200 ✅
   findings count: 52 ✅
   ✅
```

### 5B — Still Running (pending)

```powershell
# Start a new analysis and immediately query before it completes
$newAnalysis = curl.exe -s -X POST http://localhost:8080/v1/analysis `
  -H "Content-Type: application/json" -H "X-API-Key: dev-key" -H "X-Client-ID: dev-client" `
  -d '{"repo_url":"https://github.com/FlppFer/vulnerable_mcp_server.git","branch":"main"}' | ConvertFrom-Json
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/analysis/$($newAnalysis.analysis_id)/result `
  -H "X-API-Key: dev-key" -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 202, `{"error":"analysis_pending"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 6: Get Merged Result (GET /v1/analysis/{id}/result/full)

### 6A — Completed Analysis (static + agentic)

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/analysis/$ANALYSIS_ID/result/full `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 200, JSON with `static_result` (findings) and `agentic_result` fields.

```
📋 Result:
   HTTP Status: 200 ✅
   static findings: 52 ✅
   agentic findings: 4 (mock) ✅
   ✅
```

---

## Test 7: Agentic Callback (POST /v1/agentic_analysis)

> Simulates what the Python worker POSTs back after analysis. Use an `analysis_id` from a completed analysis.

### 7A — Happy Path

```powershell
$agenticBody = "{`"analysis_id`":`"$ANALYSIS_ID`",`"findings`":[{`"category`":`"tool_poisoning`",`"description`":`"Manual test finding`",`"file_path`":`"test.py`",`"severity`":`"high`",`"confidence`":0.9,`"suggestion`":`"Fix it`"}],`"summary`":`"Manual agentic test`",`"model_used`":`"gpt-4o-mini`",`"timestamp`":`"2026-04-12T12:00:00Z`"}"
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/agentic_analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d $agenticBody
```

**Expected:** HTTP 200, `{"status":"received"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

### 7B — Missing analysis_id

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/v1/agentic_analysis `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d '{"findings":[],"summary":"test"}'
```

**Expected:** HTTP 400, `{"error":"missing_field"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 8: Get Agentic Result (GET /v1/agentic_analysis/{id}/result)

### 8A — After Agentic Completion

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/agentic_analysis/$ANALYSIS_ID/result `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 200, JSON with agentic findings.

```
📋 Result:
   HTTP Status: ___
   findings count: ___
   ✅ / ❌
```

### 8B — Non-Existent ID

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/v1/agentic_analysis/does-not-exist/result `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

**Expected:** HTTP 404, `{"error":"not_found"}`

```
📋 Result:
   HTTP Status: ___
   ✅ / ❌
```

---

## Test 9: Metrics & Observability

### 9A — Health Check

```powershell
curl.exe -s -w "`nHTTP_STATUS:%{http_code}" http://localhost:8080/health
```

**Expected:** HTTP 200, `{"status":"ok"}`

```
📋 Result:
   HTTP Status: 200 ✅
   ✅
```

### 9B — Prometheus Metrics

```powershell
curl.exe -s http://localhost:8080/metrics | Select-String "mcpguard"
```

**Expected:** Lines with `mcpguard_analyses_total`, `mcpguard_findings_total`, etc.

```
📋 Result:
   ✅ / ❌
```

### 9C — Grafana Dashboard

Open: http://localhost:3000/d/mcpguard-complete  
Login: `admin` / `admin`

**Expected:** MCPGuard Complete Dashboard showing all panels with data.

```
📋 Result:
   ✅ / ❌
```

---

## Test Results Summary

| Test | Flow | Expected | Actual | Pass |
|------|------|----------|--------|------|
| 1A | Manual Analysis — Happy | 202 | | |
| 1B | Manual Analysis — Missing repo_url | 400 | | |
| 1C | Manual Analysis — Malformed JSON | 400 | | |
| 1D | Manual Analysis — No Auth | 401 | | |
| 1E | Manual Analysis — Wrong Key | 401 | | |
| 2A | Push Webhook — Happy | 202 | 202 | ✅ |
| 2B | Push Webhook — Missing Sig | 401 | 401 | ✅ |
| 2C | Push Webhook — Invalid Sig | 401 | 401 | ✅ |
| 2D | Push Webhook — Unknown Event | 200 | 200 | ✅ |
| 3A | PR Webhook — Opened | 202 | | |
| 3B | PR Webhook — Closed | 200 | | |
| 4A | Status — Valid ID | 200 | 200 | ✅ |
| 4B | Status — Unknown ID | 404 | | |
| 5A | Static Result — Completed | 200 | 200 (52 findings) | ✅ |
| 5B | Static Result — Pending | 202 | | |
| 6A | Merged Result — Completed | 200 | 200 | ✅ |
| 7A | Agentic Callback — Happy | 200 | | |
| 7B | Agentic Callback — Missing ID | 400 | | |
| 8A | Agentic Result — Completed | 200 | | |
| 8B | Agentic Result — Unknown ID | 404 | | |
| 9A | Health Check | 200 | 200 | ✅ |
| 9B | Prometheus Metrics | lines | | |
| 9C | Grafana Dashboard | visible | | | |
