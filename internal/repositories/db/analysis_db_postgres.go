package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type postgresAnalysisRepository struct {
	db *gorm.DB
}

// NewPostgresAnalysisRepository opens a Postgres connection using the supplied DSN
// and auto-migrates the analysis schema. Example DSN:
//
//	postgres://user:pass@host:5432/dbname?sslmode=disable
func NewPostgresAnalysisRepository(dsn string) (DatabaseClient, error) {
	if dsn == "" {
		return nil, errors.New("postgres DSN is empty")
	}

	slog.Info("Opening Postgres database", "dsn_suffix", maskDSN(dsn))
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open Postgres DB: %w", err)
	}

	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("postgres migration failed: %w", err)
	}

	return &postgresAnalysisRepository{db: db}, nil
}

func (r *postgresAnalysisRepository) Create(ctx context.Context, a *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Create(a).Error
}

func (r *postgresAnalysisRepository) Update(ctx context.Context, a *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Save(a).Error
}

func (r *postgresAnalysisRepository) FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error) {
	var entity repositories.AnalysisEntity
	err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find analysis entity: %w", err)
	}
	return &entity, nil
}

// maskDSN hides credentials from log output, keeping host/db hints.
func maskDSN(dsn string) string {
	// Show only the last 30 chars so credentials don't leak.
	if len(dsn) <= 30 {
		return "***"
	}
	return "..." + dsn[len(dsn)-30:]
}
