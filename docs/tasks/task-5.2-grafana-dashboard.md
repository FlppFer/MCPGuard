# Task 5.2: Grafana Dashboard Definition

| Field | Value |
|-------|-------|
| **ID** | task-5.2 |
| **Phase** | 5 — Observability |
| **Priority** | Low |
| **Effort** | Small |
| **Status** | Not Started |
| **Dependencies** | task-5.1 (Prometheus Metrics), task-2.2 (Docker Compose) |

---

## Functional Specification

### Problem Statement

Even after metrics are exposed via Prometheus, operators need pre-built dashboards to visualize MCPGuard's operational health. Without dashboards, raw metrics are difficult to interpret.

### Expected Behavior

1. A Grafana dashboard is provisioned automatically when `docker compose` starts.
2. The dashboard shows: analyses per hour, findings by severity, analysis duration, error rate, and service health.
3. Prometheus is pre-configured as a data source pointing to the MCPGuard API's `/metrics` endpoint.

### Acceptance Criteria

- `docker compose --profile observability up` starts Prometheus + Grafana + MCPGuard API.
- Grafana at `http://localhost:3000` shows the MCPGuard dashboard with live data.
- No manual configuration needed — dashboard and datasource are auto-provisioned.

---

## Technical Specification

### Prometheus Config

Create `deploy/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "mcpguard-api"
    static_configs:
      - targets: ["mcpguard-api:8080"]
    metrics_path: /metrics
```

### Grafana Provisioning

Create `deploy/grafana/provisioning/datasources.yaml`:

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

Create `deploy/grafana/provisioning/dashboards.yaml`:

```yaml
apiVersion: 1
providers:
  - name: "MCPGuard"
    orgId: 1
    folder: ""
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
```

Create `deploy/grafana/dashboards/mcpguard.json`:

A Grafana dashboard JSON with panels for:
- **Analyses/hour** — `rate(mcpguard_analyses_total[1h])`
- **Findings by severity** — bar chart of `mcpguard_findings_total` grouped by `severity`
- **Analysis duration** — histogram of `mcpguard_analysis_duration_seconds`
- **HTTP request rate** — `rate(http_requests_total[5m])` by path
- **HTTP error rate** — `rate(http_requests_total{status=~"5.."}[5m])`
- **HTTP latency (p99)** — `histogram_quantile(0.99, http_request_duration_seconds_bucket)`

### Docker Compose Additions

Add to `docker-compose.yaml`:

```yaml
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    profiles:
      - observability

  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./deploy/grafana/provisioning:/etc/grafana/provisioning
      - ./deploy/grafana/dashboards:/var/lib/grafana/dashboards
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
    depends_on:
      - prometheus
    profiles:
      - observability
```

### Files to Create

| File | Purpose |
|------|---------|
| `deploy/prometheus/prometheus.yml` | Prometheus scrape config |
| `deploy/grafana/provisioning/datasources.yaml` | Auto-provision Prometheus datasource |
| `deploy/grafana/provisioning/dashboards.yaml` | Auto-provision dashboard directory |
| `deploy/grafana/dashboards/mcpguard.json` | MCPGuard dashboard definition |

### Files to Modify

| File | Change |
|------|--------|
| `docker-compose.yaml` | Add `prometheus` and `grafana` services under `observability` profile |

### Testing

1. `docker compose --profile observability up`
2. Visit `http://localhost:9090/targets` — verify MCPGuard target is UP.
3. Visit `http://localhost:3000` — verify MCPGuard dashboard loads with panels.
4. Trigger an analysis → verify dashboard panels update.
