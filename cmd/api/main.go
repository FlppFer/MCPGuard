package api

import (
	"context"
	"log/slog"

	"github.com/FlppFer/MCPGuard/cmd/api/setup"
	"github.com/FlppFer/MCPGuard/config"
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

	resources, err :=

	//resources, err := setup
		setup.InitRoutes()
}
