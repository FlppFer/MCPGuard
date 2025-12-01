package obj_storage

import (
	"context"
	"fmt"

	"github.com/FlppFer/MCPGuard/config"
)

type StorageRepository interface {
	UploadFile(ctx context.Context, key string, localPath string) error
	DownloadFile(ctx context.Context, key string) ([]byte, error)
	GetFileURL(key string) (string, error)
}

// NewObjectStorageClient creates a storage client based on configuration
func NewObjectStorageClient(cfg *config.ObjectStorageConfig) (StorageRepository, error) {
	if cfg == nil {
		return nil, fmt.Errorf("object storage configuration is nil")
	}

	if cfg.Mock {
		localStorage, err := NewLocalStorage(cfg.BasePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create local storage: %w", err)
		}
		return localStorage, nil
	}

	// Production S3 storage
	if cfg.S3 == nil {
		return nil, fmt.Errorf("S3 configuration is required for production mode")
	}

	ctx := context.Background()
	return NewS3Storage(
		ctx,
		cfg.S3.Bucket,
		cfg.S3.Endpoint,
		cfg.S3.Region,
		cfg.S3.ForcePathStyle,
	)
}
