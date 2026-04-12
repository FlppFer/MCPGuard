package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FlppFer/MCPGuard/cmd/api/setup"
	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/service/static_analysis"
	"github.com/FlppFer/MCPGuard/internal/worker"

	_ "github.com/FlppFer/MCPGuard/internal/service/static_analysis/languages/python/rules"
)

func main() {
	ctx := context.Background()

	if err := run(ctx); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	configureSlog(cfg.LogLevel)

	mode := strings.ToLower(os.Getenv("MODE"))
	switch mode {
	case "worker":
		return runWorker(ctx, cfg)
	default:
		return runAPI(ctx, cfg)
	}
}

func runAPI(ctx context.Context, cfg *config.Config) error {
	slog.Debug("MCPGuard - Initializing API server")

	resources := setup.Bootstrap(ctx, cfg)
	router := setup.NewRouter(resources)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		slog.Info("Starting HTTP server", "port", 8080)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	// Wait for interrupt signal
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	slog.Info("Shutting down gracefully...")

	// Close publisher connection
	if resources.Publisher != nil {
		if err := resources.Publisher.Close(); err != nil {
			slog.Error("Failed to close publisher", "error", err)
		}
	}

	// Give in-flight requests 30 seconds to complete
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Forced shutdown", "error", err)
		return err
	}

	slog.Info("Server stopped")
	return nil
}

func runWorker(ctx context.Context, cfg *config.Config) error {
	slog.Info("MCPGuard - Starting worker mode")

	if cfg.MessagingCfg == nil || !cfg.MessagingCfg.Enabled || cfg.MessagingCfg.RabbitMQURL == "" {
		return fmt.Errorf("messaging must be enabled with a valid rabbitmq_url for worker mode")
	}

	resources := setup.Bootstrap(ctx, cfg)

	analyzer := static_analysis.NewService(static_analysis.WithPersistence(false))

	w, err := worker.NewStaticAnalysisWorker(
		cfg.MessagingCfg.RabbitMQURL,
		resources.DBClient,
		resources.StorageClient,
		analyzer,
		resources.AgenticService,
		resources.AgenticEnabled,
	)
	if err != nil {
		return fmt.Errorf("failed to create worker: %w", err)
	}
	defer w.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return w.Start(ctx)
}

func configureSlog(levelStr string) {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
