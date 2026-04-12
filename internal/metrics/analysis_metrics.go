package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AnalysesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_analyses_total",
		Help: "Total number of analyses triggered",
	}, []string{"trigger_type", "status"})

	AnalysisDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpguard_analysis_duration_seconds",
		Help:    "Time taken to complete static analysis",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	})

	FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_findings_total",
		Help: "Total number of security findings detected",
	}, []string{"severity"})
)
