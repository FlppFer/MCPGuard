package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const defaultLocalDBPath = "./data/local.db"

type LocalSQLiteAnalysisRepository struct {
	db     *gorm.DB
	dbPath string
}

// NewLocalSQLiteAnalysisRepository creates a file-based SQLite repository for local development.
// If dbPath is empty, it defaults to "./data/local.db"
func NewLocalSQLiteAnalysisRepository(dbPath string) (DatabaseClient, error) {
	if dbPath == "" {
		dbPath = defaultLocalDBPath
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	slog.Info("Opening local SQLite database", "path", dbPath)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open local SQLite DB: %w", err)
	}

	// Auto-migrate model
	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("local DB migration failed: %w", err)
	}

	return &LocalSQLiteAnalysisRepository{db: db, dbPath: dbPath}, nil
}

// NewMockSQLiteAnalysisRepository creates an in-memory SQLite repository for testing.
func NewMockSQLiteAnalysisRepository() (DatabaseClient, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open mock SQLite DB: %w", err)
	}

	// Auto-migrate model
	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("mock DB migration failed: %w", err)
	}

	return &LocalSQLiteAnalysisRepository{db: db, dbPath: ":memory:"}, nil
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

// DBPath returns the path to the database file
func (r *LocalSQLiteAnalysisRepository) DBPath() string {
	return r.dbPath
}
