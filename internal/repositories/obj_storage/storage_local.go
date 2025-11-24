package obj_storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

type LocalStorage struct {
	basePath string
}

func NewLocalStorage(basePath string) *LocalStorage {
	os.MkdirAll(basePath, 0755)
	return &LocalStorage{basePath: basePath}
}

func (l *LocalStorage) UploadFile(ctx context.Context, key string, localPath string) error {
	dstPath := filepath.Join(l.basePath, key)
	os.MkdirAll(filepath.Dir(dstPath), 0755)

	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func (l *LocalStorage) DownloadFile(ctx context.Context, key string) ([]byte, error) {
	filePath := filepath.Join(l.basePath, key)
	return os.ReadFile(filePath)
}

func (l *LocalStorage) GetFileURL(key string) (string, error) {
	return filepath.Join(l.basePath, key), nil
}
