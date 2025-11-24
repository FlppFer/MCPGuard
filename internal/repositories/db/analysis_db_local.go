package db

import (
	"context"
	"fmt"

	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type MockSQLiteAnalysisRepository struct {
	db *gorm.DB
}

func NewMockSQLiteAnalysisRepository() (DatabaseClient, error) {

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open mock SQLite DB: %w", err)
	}

	// Auto-migrate model
	if err := db.AutoMigrate(&repositories.AnalysisEntity{}); err != nil {
		return nil, fmt.Errorf("mock DB migration failed: %w", err)
	}

	return &MockSQLiteAnalysisRepository{db: db}, nil
}

func (m *MockSQLiteAnalysisRepository) Create(ctx context.Context, analysis *repositories.AnalysisEntity) error {
	return m.db.WithContext(ctx).Create(analysis).Error
}

func (m *MockSQLiteAnalysisRepository) Update(ctx context.Context, analysis *repositories.AnalysisEntity) error {
	return m.db.WithContext(ctx).Save(analysis).Error
}

func (m *MockSQLiteAnalysisRepository) FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error) {
	var entity repositories.AnalysisEntity
	err := m.db.WithContext(ctx).First(&entity, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}
