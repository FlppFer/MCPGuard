package worker

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/FlppFer/MCPGuard/internal/messaging"
	"github.com/FlppFer/MCPGuard/internal/metrics"
	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	repositories2 "github.com/FlppFer/MCPGuard/internal/model/repositories"
	"github.com/FlppFer/MCPGuard/internal/repositories/db"
	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
	"github.com/FlppFer/MCPGuard/internal/service"
	ghintegration "github.com/FlppFer/MCPGuard/internal/service/github_integration"
	servicemodel "github.com/FlppFer/MCPGuard/internal/service/model"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/utils"
)

// StaticAnalysisWorker consumes analysis jobs from a RabbitMQ queue and processes them.
type StaticAnalysisWorker struct {
	conn             *amqp.Connection
	channel          *amqp.Channel
	dbRepo           db.DatabaseClient
	storageRepo      obj_storage.StorageRepository
	analyzer         static_analysis.Service
	agenticSvc       service.AgenticAnalysisService
	agenticOn        bool
	prCommentService ghintegration.PRCommentService
}

// NewStaticAnalysisWorker creates a new worker connected to the given RabbitMQ URL.
func NewStaticAnalysisWorker(
	rabbitURL string,
	dbRepo db.DatabaseClient,
	storageRepo obj_storage.StorageRepository,
	analyzer static_analysis.Service,
	agenticSvc service.AgenticAnalysisService,
	agenticOn bool,
	prCommentService ghintegration.PRCommentService,
) (*StaticAnalysisWorker, error) {
	conn, err := amqp.Dial(rabbitURL)
	if err != nil {
		return nil, fmt.Errorf("worker: failed to connect to RabbitMQ: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("worker: failed to open channel: %w", err)
	}

	// Declare queue to ensure it exists
	_, err = ch.QueueDeclare(messaging.QueueStaticAnalysis, true, false, false, false, nil)
	if err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("worker: failed to declare queue: %w", err)
	}

	// Fair dispatch — one message at a time per worker
	if err := ch.Qos(1, 0, false); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("worker: failed to set QoS: %w", err)
	}

	return &StaticAnalysisWorker{
		conn:             conn,
		channel:          ch,
		dbRepo:           dbRepo,
		storageRepo:      storageRepo,
		analyzer:         analyzer,
		agenticSvc:       agenticSvc,
		agenticOn:        agenticOn,
		prCommentService: prCommentService,
	}, nil
}

// Start begins consuming messages. Blocks until ctx is cancelled.
func (w *StaticAnalysisWorker) Start(ctx context.Context) error {
	msgs, err := w.channel.Consume(
		messaging.QueueStaticAnalysis,
		"",    // consumer tag (auto-generated)
		false, // auto-ack off — we ack/nack manually
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,
	)
	if err != nil {
		return fmt.Errorf("worker: failed to start consuming: %w", err)
	}

	slog.Info("Worker started, waiting for analysis jobs", "queue", messaging.QueueStaticAnalysis)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Worker shutting down")
			return nil
		case msg, ok := <-msgs:
			if !ok {
				return fmt.Errorf("worker: message channel closed")
			}
			w.handleMessage(ctx, msg)
		}
	}
}

// Close shuts down the channel and connection.
func (w *StaticAnalysisWorker) Close() error {
	if err := w.channel.Close(); err != nil {
		return err
	}
	return w.conn.Close()
}

func (w *StaticAnalysisWorker) handleMessage(ctx context.Context, msg amqp.Delivery) {
	var job messaging.AnalysisJobMessage
	if err := json.Unmarshal(msg.Body, &job); err != nil {
		slog.Error("Worker: failed to unmarshal job message", "error", err)
		msg.Nack(false, false) // discard malformed message
		return
	}

	slog.Info("Worker: processing analysis job", "analysis_id", job.AnalysisID)

	if err := w.processJob(ctx, &job); err != nil {
		// If the analysis entity is missing from the DB, the message is unrecoverable
		// (e.g. stale job from a previous schema or dropped DB). Discard rather than
		// requeue forever.
		if strings.Contains(err.Error(), "record not found") {
			slog.Warn("Worker: discarding unrecoverable job", "analysis_id", job.AnalysisID, "error", err)
			msg.Nack(false, false)
			metrics.QueueConsumeTotal.WithLabelValues(messaging.QueueStaticAnalysis, "discarded").Inc()
			return
		}
		slog.Error("Worker: job failed, requeuing", "analysis_id", job.AnalysisID, "error", err)
		msg.Nack(false, true) // requeue for retry
		metrics.QueueConsumeTotal.WithLabelValues(messaging.QueueStaticAnalysis, "failure").Inc()
		return
	}

	msg.Ack(false)
	metrics.QueueConsumeTotal.WithLabelValues(messaging.QueueStaticAnalysis, "success").Inc()
	slog.Info("Worker: job completed successfully", "analysis_id", job.AnalysisID)
}

func (w *StaticAnalysisWorker) processJob(ctx context.Context, job *messaging.AnalysisJobMessage) error {
	entity, err := w.dbRepo.FindByID(ctx, job.AnalysisID)
	if err != nil {
		return fmt.Errorf("failed to find analysis entity: %w", err)
	}

	// 1. Download source archive from S3
	stageStart := time.Now()
	entity.Status = repositories2.StatusDownloadingRepo.String()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	metrics.AnalysisStageTransitions.WithLabelValues("queued", "downloading").Inc()

	sourceData, err := w.storageRepo.DownloadFile(ctx, job.SourceKey)
	if err != nil {
		return w.failJob(ctx, entity, fmt.Errorf("failed to download source archive: %w", err))
	}
	metrics.AnalysisStageDuration.WithLabelValues("downloading").Observe(time.Since(stageStart).Seconds())

	// 2. Extract zip to temp directory
	extractDir, err := w.extractZip(job.AnalysisID, sourceData)
	if err != nil {
		return w.failJob(ctx, entity, fmt.Errorf("failed to extract source archive: %w", err))
	}
	defer os.RemoveAll(extractDir)

	// 3. Parse repository files
	stageStart = time.Now()
	entity.Status = repositories2.StatusParsingFiles.String()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	metrics.AnalysisStageTransitions.WithLabelValues("downloading", "parsing").Inc()

	parsedFiles, err := utils.ParseRepositoryFiles(extractDir)
	if err != nil {
		return w.failJob(ctx, entity, fmt.Errorf("failed to parse files: %w", err))
	}
	metrics.AnalysisStageDuration.WithLabelValues("parsing").Observe(time.Since(stageStart).Seconds())

	// 4. Run static analysis
	stageStart = time.Now()
	entity.Status = repositories2.StatusStaticAnalysisRunning.String()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	metrics.AnalysisStageTransitions.WithLabelValues("parsing", "static_analysis").Inc()

	analysisStart := time.Now()
	result, err := w.analyzer.RunAnalysis(ctx, job.AnalysisID, parsedFiles)
	if err != nil {
		metrics.AnalysesTotal.WithLabelValues("worker", "failure").Inc()
		return w.failJob(ctx, entity, fmt.Errorf("static analysis failed: %w", err))
	}

	metrics.AnalysisDuration.Observe(time.Since(analysisStart).Seconds())
	metrics.AnalysisStageDuration.WithLabelValues("static_analysis").Observe(time.Since(stageStart).Seconds())
	for _, f := range result.Findings {
		metrics.FindingsTotal.WithLabelValues(f.Severity).Inc()
	}

	// 5. Upload results to S3
	if err := w.uploadResult(ctx, job.AnalysisID, result); err != nil {
		metrics.AnalysesTotal.WithLabelValues("worker", "failure").Inc()
		return w.failJob(ctx, entity, fmt.Errorf("failed to upload results: %w", err))
	}

	// 6. Update status
	entity.Status = repositories2.StatusStaticAnalysisDone.String()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	metrics.AnalysesTotal.WithLabelValues("worker", "success").Inc()
	metrics.AnalysisStageTransitions.WithLabelValues("static_analysis", "done").Inc()

	// 7. Post PR comment if this was triggered by a pull_request event
	if job.PRNumber > 0 && w.prCommentService != nil {
		if err := w.prCommentService.PostFindings(ctx, job.RepoFullName, job.PRNumber, result); err != nil {
			slog.Warn("Worker: failed to post PR comment", "analysis_id", job.AnalysisID, "error", err)
		}
	}

	// 8. Optionally trigger agentic analysis
	if w.agenticOn {
		w.submitAgentic(ctx, entity, job, result)
	}

	return nil
}

func (w *StaticAnalysisWorker) failJob(ctx context.Context, entity *repositories2.AnalysisEntity, err error) error {
	entity.Status = repositories2.StatusFailed.String()
	entity.ErrorMessage = err.Error()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	return err
}

func (w *StaticAnalysisWorker) extractZip(analysisID string, data []byte) (string, error) {
	tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("mcpguard_worker_%s.zip", analysisID))
	if err := os.WriteFile(tmpZip, data, 0644); err != nil {
		return "", err
	}
	defer os.Remove(tmpZip)

	extractDir := filepath.Join(os.TempDir(), "mcpguard_worker", analysisID)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", err
	}

	r, err := zip.OpenReader(tmpZip)
	if err != nil {
		return "", err
	}
	defer r.Close()

	for _, f := range r.File {
		targetPath := filepath.Join(extractDir, f.Name)

		// Prevent zip slip
		if !filepath.HasPrefix(targetPath, extractDir) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return "", err
		}

		outFile, err := os.Create(targetPath)
		if err != nil {
			return "", err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return "", err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return "", err
		}
	}

	return extractDir, nil
}

func (w *StaticAnalysisWorker) uploadResult(ctx context.Context, analysisID string, result interface{}) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(service.TmpFileStaticResult, analysisID))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	s3Key := fmt.Sprintf(service.S3KeyStaticResult, analysisID)
	return w.storageRepo.UploadFile(ctx, s3Key, tmpFile)
}

func (w *StaticAnalysisWorker) submitAgentic(ctx context.Context, entity *repositories2.AnalysisEntity, job *messaging.AnalysisJobMessage, staticResult *servicemodel.AnalysisResult) {
	entity.Status = repositories2.StatusWaitingAgentAnalysis.String()
	entity.UpdatedAt = time.Now()
	w.dbRepo.Update(ctx, entity)
	metrics.AnalysisStageTransitions.WithLabelValues("done", "waiting_agentic").Inc()

	var staticFindings []httpmodel.StaticFindingContext
	if staticResult != nil {
		for _, f := range staticResult.Findings {
			staticFindings = append(staticFindings, httpmodel.StaticFindingContext{
				RuleID:   f.RuleID,
				FilePath: f.FilePath,
				Line:     f.Line,
				Severity: f.Severity,
				Message:  f.Message,
			})
		}
	}

	var changedFiles []string
	if job.PRNumber > 0 && w.prCommentService != nil {
		if files, err := w.prCommentService.FetchChangedFiles(ctx, job.RepoFullName, job.PRNumber); err != nil {
			slog.Warn("Worker: failed to fetch PR changed files, will analyze full repo",
				"analysis_id", job.AnalysisID, "error", err)
		} else {
			changedFiles = files
		}
	}

	req := &httpmodel.AgenticAnalysisRequestDTO{
		AnalysisID:     job.AnalysisID,
		RepoURL:        job.RepoURL,
		Branch:         job.Branch,
		Commit:         job.Commit,
		SourceKey:      job.SourceKey,
		StaticFindings: staticFindings,
		PRChangedFiles: changedFiles,
	}

	if err := w.agenticSvc.SubmitForAnalysis(ctx, req); err != nil {
		slog.Warn("Worker: failed to submit agentic analysis, continuing without it",
			"analysis_id", job.AnalysisID, "error", err)
		entity.Status = repositories2.StatusStaticAnalysisDone.String()
		entity.UpdatedAt = time.Now()
		w.dbRepo.Update(ctx, entity)
	}
}
