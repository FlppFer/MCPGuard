# MCPGuard

Automated security analysis pipeline for Model Context Protocol (MCP) implementations.  
Combines static analysis (31 AST rules via tree-sitter) with agentic LLM analysis (Google Gemini), triggered by GitHub webhooks.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Profiles](#profiles)
- [Common Commands](#common-commands)
- [Service Reference](#service-reference)
- [Workflows](#workflows)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Docker Desktop (with WSL2 backend on Windows)
- A `.env` file in this directory (copy from `.env.example`)

---

## Configuration

Copy the example and fill in your values:

```powershell
cp .env.example .env
```

Minimum required variables:

```env
SCOPE=docker
GITHUB_WEBHOOK_SECRET=your-webhook-secret
MCPGUARD_API_KEYS=client1:apikey1
GITHUB_TOKEN=github_pat_xxxxxxxxxxxx   # optional — only for private repos / PR comments
```

---

## Profiles

Services are grouped into profiles. You can combine multiple profiles.

| Profile | Services included |
|---|---|
| *(none)* | `mcpguard-api`, `localstack` |
| `queue` | + `rabbitmq`, `mcpguard-worker` |
| `observability` | + `prometheus`, `grafana`, `loki`, `promtail`, `cadvisor`, `node-exporter` |
| `all` | Everything above |

---

## Common Commands

### Start

```powershell
# Full stack (all services)
docker compose --profile all up -d

# API only (no queue, no observability)
docker compose up -d

# API + queue
docker compose --profile queue up -d

# API + observability
docker compose --profile observability up -d
```

### Stop

```powershell
# Stop all — keep volumes (data preserved)
docker compose --profile all down

# Stop all — wipe volumes (full reset)
docker compose --profile all down -v

# Stop and remove orphaned containers
docker compose --profile all down --remove-orphans
```

### Rebuild & Redeploy

```powershell
# Rebuild everything and restart
docker compose --profile all up -d --build --force-recreate

# Rebuild only changed services, leave infra containers untouched
docker compose --profile all up -d --build --no-deps

# Rebuild and restart a single service
docker compose up -d --build mcpguard-api
docker compose --profile queue up -d --build mcpguard-worker
```

### Logs

```powershell
# Tail all services
docker compose --profile all logs -f

# Tail a specific service
docker compose logs -f mcpguard-api
docker compose --profile queue logs -f mcpguard-worker

# Last 100 lines of a service
docker compose logs --tail=100 mcpguard-api
```

### Status

```powershell
# List running containers and their status
docker compose --profile all ps

# Resource usage (CPU/memory)
docker stats
```

### Restart a Single Service

```powershell
# Restart without rebuilding (picks up env changes)
docker compose restart mcpguard-api

# Restart observability stack (e.g. after dashboard changes)
docker compose --profile observability restart grafana
```

---

## Service Reference

| Service | Port | Description |
|---|---|---|
| `mcpguard-api` | `8080` | Main API — webhook receiver, analysis orchestrator |
| `mcpguard-worker` | — | Queue consumer for static analysis jobs |
| `rabbitmq` | `5672` / `15672` | Message queue (management UI on 15672) |
| `localstack` | `4566` | Local AWS S3 for artifact storage |
| `prometheus` | `9090` | Metrics scraper |
| `grafana` | `3000` | Dashboards (admin / admin) |
| `loki` | `3100` | Log aggregation |
| `promtail` | — | Log shipper (Docker → Loki) |
| `cadvisor` | `8081` | Container resource metrics |
| `node-exporter` | `9100` | Host resource metrics |

---

## Workflows

### Trigger an Analysis (webhook)

```powershell
# Push event
curl -X POST http://localhost:8080/webhook/github `
  -H "Content-Type: application/json" `
  -H "X-Hub-Signature-256: sha256=<hmac>" `
  -d '{"ref":"refs/heads/main","repository":{"clone_url":"https://github.com/org/repo"}}'
```

### Trigger an Analysis (direct API)

```powershell
curl -X POST http://localhost:8080/api/v1/analyze `
  -H "Content-Type: application/json" `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client" `
  -d '{"repo_url":"https://github.com/org/repo","branch":"main"}'
```

### Check Analysis Status

```powershell
curl http://localhost:8080/api/v1/analysis/<analysis_id> `
  -H "X-API-Key: dev-key" `
  -H "X-Client-ID: dev-client"
```

---

## Troubleshooting

### API fails to start (localstack not ready)
LocalStack has a healthcheck — the API waits for it. If it times out:
```powershell
docker compose logs localstack
docker compose restart localstack
```

### Worker not processing jobs
Ensure the `queue` or `all` profile is active and RabbitMQ is healthy:
```powershell
docker compose --profile queue ps
docker compose --profile queue logs rabbitmq
```

### Grafana shows no data
1. Verify Prometheus is scraping: http://localhost:9090/targets
2. Check the time range in Grafana — set to **Last 1 hour** or wider
3. Reload dashboards: `docker compose --profile observability restart grafana`

### Logs not appearing in Grafana/Loki
```powershell
docker compose --profile observability logs promtail
# Verify labels are being picked up:
curl "http://localhost:3100/loki/api/v1/label/service/values"
```

### Full reset (nuclear option)
```powershell
docker compose --profile all down -v --remove-orphans
docker compose --profile all up -d --build
```