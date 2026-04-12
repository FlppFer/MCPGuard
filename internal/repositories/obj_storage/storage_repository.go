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

// NewObjectStorageClient creates a storage client based on the configured provider.
// Supported providers: "localstack" (S3-compatible local dev), "s3" (AWS S3 production).
func NewObjectStorageClient(cfg *config.ObjectStorageConfig) (StorageRepository, error) {
	if cfg == nil {
		return nil, fmt.Errorf("object storage configuration is nil")
	}

	switch cfg.Provider {
	case "localstack":
		storage, err := NewLocalStorage(cfg.BasePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create localstack storage: %w", err)
		}
		return storage, nil

	case "s3":
		if cfg.S3 == nil {
			return nil, fmt.Errorf("S3 configuration is required when provider is 's3'")
		}
		ctx := context.Background()
		return NewS3Storage(
			ctx,
			cfg.S3.Bucket,
			cfg.S3.Endpoint,
			cfg.S3.Region,
			cfg.S3.ForcePathStyle,
		)

	default:
		return nil, fmt.Errorf("unknown object storage provider: %q (must be 'localstack' or 's3')", cfg.Provider)
	}
}
