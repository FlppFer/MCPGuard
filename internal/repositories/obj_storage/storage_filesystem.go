package obj_storage

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// FilesystemStorage is a simple file-based storage backend for local development.
// It stores objects as files under a base directory, using the object key as a relative path.
// No Docker or external services required.
type FilesystemStorage struct {
	basePath string
}

// NewFilesystemStorage creates a new filesystem-backed storage rooted at basePath.
func NewFilesystemStorage(basePath string) (*FilesystemStorage, error) {
	abs, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base path: %w", err)
	}

	if err := os.MkdirAll(abs, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	slog.Info("Filesystem storage initialized", "path", abs)
	return &FilesystemStorage{basePath: abs}, nil
}

// UploadFile copies a local file into the storage directory under the given key.
func (fs *FilesystemStorage) UploadFile(_ context.Context, key string, localPath string) error {
	dst := filepath.Join(fs.basePath, filepath.FromSlash(key))

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create directories for key %s: %w", key, err)
	}

	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	slog.Debug("File stored", "key", key, "path", dst)
	return nil
}

// DownloadFile reads the object from the filesystem and returns its bytes.
func (fs *FilesystemStorage) DownloadFile(_ context.Context, key string) ([]byte, error) {
	path := filepath.Join(fs.basePath, filepath.FromSlash(key))

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file for key %s: %w", key, err)
	}

	return data, nil
}

// GetFileURL returns a file:// URL for the object.
func (fs *FilesystemStorage) GetFileURL(key string) (string, error) {
	path := filepath.Join(fs.basePath, filepath.FromSlash(key))
	return "file://" + filepath.ToSlash(path), nil
}
