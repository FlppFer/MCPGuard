package db

import (
	"context"

	"github.com/FlppFer/MCPGuard/internal/model/repositories"
	"gorm.io/gorm"
)

type sqliteAnalysisRepository struct {
	db *gorm.DB
}

func NewSQLiteAnalysisRepository(db *gorm.DB) DatabaseClient {
	return &sqliteAnalysisRepository{db: db}
}

func (r *sqliteAnalysisRepository) Create(ctx context.Context, a *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Create(a).Error
}

func (r *sqliteAnalysisRepository) Update(ctx context.Context, a *repositories.AnalysisEntity) error {
	return r.db.WithContext(ctx).Save(a).Error
}

func (r *sqliteAnalysisRepository) FindByID(ctx context.Context, id string) (*repositories.AnalysisEntity, error) {
	var analysis repositories.AnalysisEntity
	err := r.db.WithContext(ctx).First(&analysis, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &analysis, nil
}
