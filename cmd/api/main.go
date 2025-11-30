package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/FlppFer/MCPGuard/cmd/api/setup"
	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/service"
)

func main() {
	ctx := context.Background()

	if err := run(ctx); err != nil {
		slog.Error(err.Error())
	}
}

func run(ctx context.Context) error {
	slog.Debug("MCPGuard - Initializing server")

	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	resources := setup.Bootstrap(ctx, cfg)

	// Initialize secrets service from environment variables
	secretsSvc := service.NewSecretsService()

	fmt.Println("MCPGuard - Initializing server")
	setup.InitRoutes(secretsSvc, resources)
	return nil
}
