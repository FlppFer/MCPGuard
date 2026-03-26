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
)

func main() {
	ctx := context.Background()

	if err := run(ctx); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	slog.Debug("MCPGuard - Initializing server")

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	configureSlog(cfg.LogLevel)

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
