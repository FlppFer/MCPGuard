# Task 5.1: Prometheus Metrics Endpoint

| Field | Value |
|-------|-------|
| **ID** | task-5.1 |
| **Phase** | 5 — Observability |
| **Priority** | Medium |
| **Effort** | Medium |
| **Status** | Not Started |
| **Dependencies** | None |

---

## Functional Specification

### Problem Statement

The MCPGuard article describes Prometheus + Grafana for monitoring. Currently, there is no `/metrics` endpoint, no HTTP request instrumentation, and no custom application metrics. In production, operators have no visibility into request rates, error rates, analysis throughput, or finding distributions.

### Expected Behavior

1. `GET /metrics` exposes Prometheus-compatible metrics in OpenMetrics format.
2. HTTP middleware automatically records request count, latency, and response size per endpoint.
3. Custom application metrics track:
   - Total analyses triggered (by trigger type: webhook vs manual).
   - Analysis duration (histogram).
   - Findings detected (by severity and rule category).
   - Current analysis status distribution.

### Acceptance Criteria

- `curl http://localhost:8080/metrics` returns Prometheus-formatted metrics.
- HTTP metrics include `method`, `path`, `status_code` labels.
- Custom `mcpguard_*` metrics are present after triggering an analysis.
- No auth required on `/metrics` (same as `/health`).

---

## Technical Specification

### New Dependency

Add to `go.mod`:
```
github.com/prometheus/client_golang v1.20.0
```

### Create `internal/middleware/metrics.go`

```go
package middleware

import (
    "net/http"
    "strconv"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "http_requests_total",
        Help: "Total number of HTTP requests",
    }, []string{"method", "path", "status"})

    httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "http_request_duration_seconds",
        Help:    "HTTP request duration in seconds",
        Buckets: prometheus.DefBuckets,
    }, []string{"method", "path"})
)

// PrometheusHTTP is a middleware that records HTTP request metrics.
func PrometheusHTTP(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        ww := &statusWriter{ResponseWriter: w, status: 200}

        next.ServeHTTP(ww, r)

        duration := time.Since(start).Seconds()
        routePattern := chi.RouteContext(r.Context()).RoutePattern()
        if routePattern == "" {
            routePattern = r.URL.Path
        }

        httpRequestsTotal.WithLabelValues(r.Method, routePattern, strconv.Itoa(ww.status)).Inc()
        httpRequestDuration.WithLabelValues(r.Method, routePattern).Observe(duration)
    })
}

type statusWriter struct {
    http.ResponseWriter
    status int
}

func (w *statusWriter) WriteHeader(status int) {
    w.status = status
    w.ResponseWriter.WriteHeader(status)
}
```

### Custom Application Metrics

Define in a new file `internal/metrics/analysis_metrics.go`:

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    AnalysesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "mcpguard_analyses_total",
        Help: "Total number of analyses triggered",
    }, []string{"trigger_type", "status"}) // trigger_type: "webhook", "manual"

    AnalysisDuration = promauto.NewHistogram(prometheus.HistogramOpts{
        Name:    "mcpguard_analysis_duration_seconds",
        Help:    "Time taken to complete static analysis",
        Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
    })

    FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "mcpguard_findings_total",
        Help: "Total number of security findings detected",
    }, []string{"severity"}) // severity: critical, high, medium, low, info
)
```

### Instrument Service Layer

In `git_webhook_service.go`, after analysis completes:

```go
// Record analysis duration
metrics.AnalysisDuration.Observe(time.Since(analysisStart).Seconds())

// Record findings by severity
for _, f := range result.Findings {
    metrics.FindingsTotal.WithLabelValues(f.Severity).Inc()
}

// Record analysis completion
metrics.AnalysesTotal.WithLabelValues(triggerType, "success").Inc()
```

### Register `/metrics` Endpoint

In `cmd/api/setup/routes.go`:

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

// In NewRouter():
r.Use(customMiddleware.PrometheusHTTP)   // HTTP metrics middleware

r.Get("/metrics", promhttp.Handler().ServeHTTP)  // alongside /health, no auth
```

### Files to Create

| File | Purpose |
|------|---------|
| `internal/middleware/metrics.go` | HTTP metrics middleware |
| `internal/metrics/analysis_metrics.go` | Custom application metrics |

### Files to Modify

| File | Change |
|------|--------|
| `cmd/api/setup/routes.go` | Register `/metrics` endpoint + HTTP metrics middleware |
| `internal/service/git_webhook_service.go` | Increment analysis and findings counters |
| `go.mod` | Add `prometheus/client_golang` |

### Testing

- Start server → `curl localhost:8080/metrics` → verify `http_requests_total` appears.
- Trigger an analysis → `curl localhost:8080/metrics` → verify `mcpguard_analyses_total` incremented.
- Verify findings counters match expected severity distribution.
