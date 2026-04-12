package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Analysis lifecycle metrics
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

	// Pipeline stage metrics
	AnalysisStageTransitions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_analysis_stage_transitions_total",
		Help: "Number of transitions between analysis stages",
	}, []string{"from_stage", "to_stage"})

	AnalysisStageDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mcpguard_analysis_stage_duration_seconds",
		Help:    "Time spent in each analysis stage",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120},
	}, []string{"stage"})

	// Repository operations
	RepoCloneDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpguard_repo_clone_duration_seconds",
		Help:    "Time taken to clone repository",
		Buckets: []float64{1, 5, 10, 30, 60, 120},
	})

	RepoCloneErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpguard_repo_clone_errors_total",
		Help: "Total number of repository clone failures",
	})

	RepoSizeBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpguard_repo_size_bytes",
		Help:    "Size of cloned repositories in bytes",
		Buckets: prometheus.ExponentialBuckets(1024*1024, 2, 10), // 1MB to 512MB
	})

	// Storage operations
	StorageUploadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mcpguard_storage_upload_duration_seconds",
		Help:    "Time taken to upload files to object storage",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30},
	}, []string{"file_type"})

	StorageDownloadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mcpguard_storage_download_duration_seconds",
		Help:    "Time taken to download files from object storage",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30},
	}, []string{"file_type"})

	StorageOperationErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_storage_operation_errors_total",
		Help: "Total number of storage operation failures",
	}, []string{"operation", "file_type"})

	// Queue metrics
	QueuePublishTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_queue_publish_total",
		Help: "Total number of messages published to queue",
	}, []string{"queue_name", "status"})

	QueuePublishDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpguard_queue_publish_duration_seconds",
		Help:    "Time taken to publish message to queue",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})

	// Agentic analysis metrics
	AgenticAnalysisSubmitted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpguard_agentic_analysis_submitted_total",
		Help: "Total number of agentic analyses submitted to worker",
	})

	AgenticAnalysisCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_agentic_analysis_completed_total",
		Help: "Total number of agentic analyses completed",
	}, []string{"status"})

	AgenticAnalysisDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpguard_agentic_analysis_duration_seconds",
		Help:    "Time taken for agentic analysis (from submission to callback)",
		Buckets: []float64{5, 10, 30, 60, 120, 300, 600},
	})

	AgenticWorkerErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_agentic_worker_errors_total",
		Help: "Total number of agentic worker errors",
	}, []string{"error_type"})

	// Database operations
	DatabaseOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mcpguard_database_operation_duration_seconds",
		Help:    "Time taken for database operations",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"operation"})

	DatabaseOperationErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpguard_database_operation_errors_total",
		Help: "Total number of database operation failures",
	}, []string{"operation"})

	// Active analyses gauge
	ActiveAnalyses = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mcpguard_active_analyses",
		Help: "Number of currently active analyses",
	}, []string{"stage"})
)
