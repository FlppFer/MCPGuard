package db

import (
	"context"
	"fmt"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/model/repositories"
)

type DatabaseClient interface {
	Create(ctx context.Context, analysis *repositories.AnalysisEntity) error
	Update(ctx context.Context, analysis *repositories.AnalysisEntity) error
	FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error)
}

func NewDatabaseClient(cfgClient *config.DatabaseConfig) (DatabaseClient, error) {
	if cfgClient.Mock {
		return NewMockSQLiteAnalysisRepository()
	}
	// TODO: real SQLite file database or PostgreSQL
	return nil, fmt.Errorf("production DB not implemented yet")
}
