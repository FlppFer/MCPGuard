# MCPGuard Observability Guide

This guide covers the comprehensive observability stack for MCPGuard, including infrastructure metrics, application flow tracking, and visualization.

---

## Architecture

```
┌─────────────────┐
│   MCPGuard API  │──┐
│   (Port 8080)   │  │
└─────────────────┘  │
                     │
┌─────────────────┐  │    ┌──────────────┐
│   cAdvisor      │──┼───▶│  Prometheus  │
│   (Port 8081)   │  │    │  (Port 9090) │
└─────────────────┘  │    └──────┬───────┘
                     │           │
┌─────────────────┐  │           │
│ Node Exporter   │──┘           │
│  (Port 9100)    │              │
└─────────────────┘              │
                                 ▼
                          ┌──────────────┐
                          │   Grafana    │
                          │  (Port 3000) │
                          └──────────────┘
```

---

## Components

### 1. **cAdvisor** (Container Metrics)
- **Port:** 8081
- **Metrics:** CPU, memory, network I/O, disk I/O per container
- **Scope:** All MCPGuard containers (API, worker, LocalStack, RabbitMQ, etc.)

### 2. **Node Exporter** (Host Metrics)
- **Port:** 9100
- **Metrics:** Host CPU, memory, disk usage, network
- **Scope:** Docker host system

### 3. **Prometheus** (Metrics Storage)
- **Port:** 9090
- **Scrapes:** MCPGuard API, cAdvisor, Node Exporter
- **Retention:** Default (15 days)

### 4. **Grafana** (Visualization)
- **Port:** 3000
- **Dashboards:** 3 pre-configured dashboards
- **Credentials:** `admin` / `admin`

---

## Metrics Catalog

### Infrastructure Metrics (from cAdvisor & Node Exporter)

| Metric | Description | Source |
|--------|-------------|--------|
| `container_cpu_usage_seconds_total` | Container CPU usage | cAdvisor |
| `container_memory_usage_bytes` | Container memory usage | cAdvisor |
| `container_network_receive_bytes_total` | Container network RX | cAdvisor |
| `container_network_transmit_bytes_total` | Container network TX | cAdvisor |
| `container_fs_reads_bytes_total` | Container disk reads | cAdvisor |
| `container_fs_writes_bytes_total` | Container disk writes | cAdvisor |
| `node_cpu_seconds_total` | Host CPU usage | Node Exporter |
| `node_memory_MemTotal_bytes` | Host total memory | Node Exporter |
| `node_memory_MemAvailable_bytes` | Host available memory | Node Exporter |
| `node_filesystem_size_bytes` | Host disk size | Node Exporter |
| `node_filesystem_avail_bytes` | Host disk available | Node Exporter |

### Application Flow Metrics (from MCPGuard API)

#### Analysis Lifecycle
- `mcpguard_analyses_total{trigger_type, status}` — Total analyses triggered
- `mcpguard_analysis_duration_seconds` — Analysis completion time
- `mcpguard_findings_total{severity}` — Security findings by severity

#### Pipeline Stages
- `mcpguard_analysis_stage_transitions_total{from_stage, to_stage}` — Stage transitions
- `mcpguard_analysis_stage_duration_seconds{stage}` — Time in each stage
- `mcpguard_active_analyses{stage}` — Currently active analyses

#### Repository Operations
- `mcpguard_repo_clone_duration_seconds` — Git clone duration
- `mcpguard_repo_clone_errors_total` — Clone failures
- `mcpguard_repo_size_bytes` — Repository size distribution

#### Storage Operations
- `mcpguard_storage_upload_duration_seconds{file_type}` — Upload time
- `mcpguard_storage_download_duration_seconds{file_type}` — Download time
- `mcpguard_storage_operation_errors_total{operation, file_type}` — Storage errors

#### Queue Operations
- `mcpguard_queue_publish_total{queue_name, status}` — Messages published
- `mcpguard_queue_publish_duration_seconds` — Publish latency

#### Agentic Analysis
- `mcpguard_agentic_analysis_submitted_total` — Jobs submitted to worker
- `mcpguard_agentic_analysis_completed_total{status}` — Jobs completed
- `mcpguard_agentic_analysis_duration_seconds` — Worker processing time
- `mcpguard_agentic_worker_errors_total{error_type}` — Worker errors

#### Database Operations
- `mcpguard_database_operation_duration_seconds{operation}` — DB query latency
- `mcpguard_database_operation_errors_total{operation}` — DB errors

#### HTTP Metrics
- `http_requests_total{method, path, status}` — HTTP request count
- `http_request_duration_seconds{method, path}` — HTTP latency

---

## Grafana Dashboards

### 1. **MCPGuard Overview** (`/d/mcpguard-overview`)
- Analyses per hour (by trigger type and status)
- Findings by severity
- Analysis duration percentiles (p50/p90/p99)
- HTTP request rate by path
- HTTP error rate (5xx)
- HTTP latency p99

### 2. **MCPGuard Infrastructure** (`/d/mcpguard-infrastructure`)
- Container CPU usage (per container)
- Container memory usage (per container)
- Container network I/O (RX/TX)
- Container disk I/O (read/write)
- Host CPU usage
- Host memory usage
- Host disk usage (with thresholds)
- Container restart count

### 3. **MCPGuard Analysis Flow** (`/d/mcpguard-flow`)
- Analysis pipeline stage transitions
- Stage duration percentiles
- Active analyses by stage
- Repository clone metrics
- Repository size distribution
- Storage operation duration
- Storage errors
- Agentic analysis flow (submitted vs completed)
- Agentic analysis duration
- Database operation latency
- Queue operations

---

## Deployment

### Start Full Observability Stack

```powershell
docker compose --profile observability up -d
```

This starts:
- MCPGuard API
- LocalStack (S3)
- cAdvisor
- Node Exporter
- Prometheus
- Grafana

### Access Dashboards

1. **Grafana:** http://localhost:3000
   - Login: `admin` / `admin`
   - Dashboards → Browse → Select a dashboard

2. **Prometheus:** http://localhost:9090
   - Query metrics directly
   - Check targets: Status → Targets

3. **cAdvisor:** http://localhost:8081
   - View container metrics directly

### Verify Metrics Collection

```powershell
# Check Prometheus targets
Invoke-WebRequest http://localhost:9090/api/v1/targets | ConvertFrom-Json

# Query a metric
Invoke-WebRequest "http://localhost:9090/api/v1/query?query=mcpguard_analyses_total" | ConvertFrom-Json
```

---

## Troubleshooting

### Dashboard Not Showing Data

1. **Check Prometheus targets:**
   - Go to http://localhost:9090/targets
   - All targets should be "UP"

2. **Check metric availability:**
   - Go to http://localhost:9090/graph
   - Query: `mcpguard_analyses_total`
   - Should return data if analyses have run

3. **Verify Grafana datasource:**
   - Grafana → Configuration → Data Sources
   - Prometheus should be listed with UID `prometheus`

### cAdvisor Not Starting (Windows)

cAdvisor requires privileged mode and specific volume mounts. If it fails:

```powershell
# Check logs
docker logs mcpguard-cadvisor-1

# On Windows, cAdvisor may have limited functionality
# Consider using Docker Desktop's built-in metrics instead
```

### High Memory Usage

Prometheus stores metrics in memory. To reduce:

1. **Reduce scrape interval** in `deploy/prometheus/prometheus.yml`:
   ```yaml
   global:
     scrape_interval: 30s  # Increase from 15s
   ```

2. **Reduce retention:**
   ```yaml
   # In docker-compose.yaml, add to prometheus command:
   command:
     - '--storage.tsdb.retention.time=7d'
   ```

---

## Custom Queries

### Top 5 Slowest Analysis Stages

```promql
topk(5, 
  histogram_quantile(0.99, 
    sum(rate(mcpguard_analysis_stage_duration_seconds_bucket[5m])) by (le, stage)
  )
)
```

### Error Rate by Endpoint

```promql
sum(rate(http_requests_total{status=~"5.."}[5m])) by (path) 
/ 
sum(rate(http_requests_total[5m])) by (path) * 100
```

### Container Memory Growth

```promql
deriv(container_memory_usage_bytes{name=~"mcpguard.*"}[1h])
```

### Agentic Analysis Success Rate

```promql
sum(rate(mcpguard_agentic_analysis_completed_total{status="success"}[5m]))
/
sum(rate(mcpguard_agentic_analysis_submitted_total[5m])) * 100
```

---

## Alerting (Future Enhancement)

To add alerting, create `deploy/prometheus/alerts.yml`:

```yaml
groups:
  - name: mcpguard
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High 5xx error rate detected"

      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes{name=~"mcpguard.*"} / 1024 / 1024 > 512
        for: 10m
        annotations:
          summary: "Container using >512MB memory"
```

Then add to `prometheus.yml`:
```yaml
rule_files:
  - /etc/prometheus/alerts.yml
```

---

## Performance Impact

### Metrics Collection Overhead

- **CPU:** <1% per container
- **Memory:** ~50MB for Prometheus, ~100MB for cAdvisor
- **Disk:** ~1GB per week for metrics storage
- **Network:** Negligible (local scraping)

### Recommendations

- **Production:** Enable all metrics
- **Development:** Use `--profile observability` to opt-in
- **CI/CD:** Disable observability to save resources

---

## Next Steps

1. **Run an analysis** to generate metrics
2. **Open Grafana** and explore the 3 dashboards
3. **Create custom dashboards** for your specific needs
4. **Set up alerting** (optional) for production monitoring
5. **Export dashboards** for version control

For questions or issues, see the main README or open an issue on GitHub.
