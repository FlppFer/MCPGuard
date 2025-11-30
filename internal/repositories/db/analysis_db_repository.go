package db

import (
	"context"
	"fmt"

	"github.com/FlppFer/MCPGuard/config"
	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DatabaseClient interface {
	Create(ctx context.Context, analysis *repositories.AnalysisEntity) error
	Update(ctx context.Context, analysis *repositories.AnalysisEntity) error
	FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error)
}

func NewDatabaseClient(cfgClient *config.DatabaseConfig) (DatabaseClient, error) {
	if cfgClient == nil {
		return nil, fmt.Errorf("database configuration is nil")
	}

	if cfgClient.Mock {
		return NewLocalSQLiteAnalysisRepository()
	}

	// Production SQLite file database stored inside resources folder
	if cfgClient.Path == "" {
		cfgClient.Path = "./resources/mcpguard.db"
	}

	db, err := gorm.Open(sqlite.Open(cfgClient.Path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite DB at %s: %w", cfgClient.Path, err)
	}

	// Auto-migrate models
	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("DB migration failed: %w", err)
	}

	return NewSQLiteAnalysisRepository(db), nil
}
