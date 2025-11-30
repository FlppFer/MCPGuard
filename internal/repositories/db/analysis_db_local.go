package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type LocalSQLiteAnalysisRepository struct {
	db *gorm.DB
}

// NewLocalSQLiteAnalysisRepository creates a file-based SQLite repository for local development.
func NewLocalSQLiteAnalysisRepository() (DatabaseClient, error) {

	slog.Info("Opening local SQLite database")
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open local SQLite DB: %w", err)
	}

	// Auto-migrate model
	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("local DB migration failed: %w", err)
	}

	return &LocalSQLiteAnalysisRepository{db: db}, nil
}

func (r *LocalSQLiteAnalysisRepository) Create(ctx context.Context, analysis *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Create(analysis).Error
}

func (r *LocalSQLiteAnalysisRepository) Update(ctx context.Context, analysis *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Save(analysis).Error
}

func (r *LocalSQLiteAnalysisRepository) FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error) {
	var entity repositories.AnalysisEntity
	err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}
