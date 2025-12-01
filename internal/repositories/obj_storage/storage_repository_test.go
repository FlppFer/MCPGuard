package obj_storage

import (
	"testing"

	"github.com/FlppFer/MCPGuard/config"
)

func TestNewObjectStorageClient_NilConfig(t *testing.T) {
	_, err := NewObjectStorageClient(nil)
	if err == nil {
		t.Fatal("Expected error for nil config, got nil")
	}
	expectedMsg := "object storage configuration is nil"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestNewObjectStorageClient_ProductionModeWithoutS3Config(t *testing.T) {
	cfg := &config.ObjectStorageConfig{
		Mock: false,
		S3:   nil,
	}

	_, err := NewObjectStorageClient(cfg)
	if err == nil {
		t.Fatal("Expected error for production mode without S3 config, got nil")
	}
	expectedMsg := "S3 configuration is required for production mode"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestNewObjectStorageClient_ProductionModeWithS3Config(t *testing.T) {
	cfg := &config.ObjectStorageConfig{
		Mock: false,
		S3: &config.S3Config{
			Bucket:         "test-bucket",
			Region:         "us-east-1",
			Endpoint:       "http://localhost:4566",
			ForcePathStyle: true,
		},
	}

	storage, err := NewObjectStorageClient(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if storage == nil {
		t.Fatal("Expected non-nil storage")
	}

	// Verify it's an S3Storage instance
	s3Storage, ok := storage.(*S3Storage)
	if !ok {
		t.Fatal("Expected S3Storage instance for production mode")
	}
	if s3Storage.bucket != "test-bucket" {
		t.Errorf("Expected bucket 'test-bucket', got '%s'", s3Storage.bucket)
	}
}
