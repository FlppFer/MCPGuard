package obj_storage

import (
	"context"
	"fmt"
)

type StorageRepository interface {
	UploadFile(ctx context.Context, key string, localPath string) error
	DownloadFile(ctx context.Context, key string) ([]byte, error)
	GetFileURL(key string) (string, error) // optional but useful
}

func NewObjectStorageClient(mock bool, basePath string) (StorageRepository, error) {
	if mock {
		return NewLocalStorage(basePath), nil
	}
	// TODO: real Amazon S3 storage client
	return nil, fmt.Errorf("production Object Storage not implemented yet")
}
