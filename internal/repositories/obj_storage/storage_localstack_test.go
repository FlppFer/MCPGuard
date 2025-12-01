//go:build integration

package obj_storage_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlppFer/MCPGuard/internal/repositories/obj_storage"
)

const testBucket = "mcpguard-test-bucket"

func TestLocalStackStorage_UploadAndDownload(t *testing.T) {
	// Create LocalStack-backed storage (starts Docker container)
	storage, err := obj_storage.NewLocalStorage(testBucket)
	if err != nil {
		t.Fatalf("Failed to create LocalStack storage: %v", err)
	}
	t.Cleanup(func() {
		storage.Stop()
	})

	ctx := context.Background()

	// Create a temp file to upload
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.json")
	testData := map[string]string{"message": "hello from localstack"}
	data, _ := json.Marshal(testData)
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Upload
	key := "analysis-results/test-analysis-123.json"
	if err := storage.UploadFile(ctx, key, testFile); err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}

	// Download
	downloaded, err := storage.DownloadFile(ctx, key)
	if err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}

	// Verify content
	var result map[string]string
	if err := json.Unmarshal(downloaded, &result); err != nil {
		t.Fatalf("Failed to unmarshal downloaded data: %v", err)
	}

	if result["message"] != "hello from localstack" {
		t.Errorf("Expected 'hello from localstack', got '%s'", result["message"])
	}

	// Test GetFileURL
	url, err := storage.GetFileURL(key)
	if err != nil {
		t.Fatalf("GetFileURL failed: %v", err)
	}
	if url == "" {
		t.Error("Expected non-empty URL")
	}
	t.Logf("Generated URL: %s", url)
}

// AnalysisResult mirrors the struct from static_analysis for testing
type AnalysisResult struct {
	AnalysisID string    `json:"analysis_id"`
	Files      int       `json:"files_analyzed"`
	Findings   []Finding `json:"findings"`
}

type Finding struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

func TestLocalStackStorage_AnalysisResultUpload(t *testing.T) {
	storage, err := obj_storage.NewLocalStorage(testBucket)
	if err != nil {
		t.Fatalf("Failed to create LocalStack storage: %v", err)
	}
	t.Cleanup(func() {
		storage.Stop()
	})

	ctx := context.Background()

	// Simulate analysis result
	result := AnalysisResult{
		AnalysisID: "analysis-abc-123",
		Files:      5,
		Findings: []Finding{
			{
				RuleID:   "DTI-002",
				Message:  "Command injection detected",
				FilePath: "/repo/main.py",
				Line:     42,
				Severity: "critical",
				Snippet:  "os.system(user_input)",
			},
		},
	}

	// Save to temp file
	tmpDir := t.TempDir()
	resultFile := filepath.Join(tmpDir, "analysis-abc-123_static.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(resultFile, data, 0644)

	// Upload to S3
	s3Key := "analysis-results/analysis-abc-123_static.json"
	if err := storage.UploadFile(ctx, s3Key, resultFile); err != nil {
		t.Fatalf("Failed to upload analysis result: %v", err)
	}

	// Download and verify
	downloaded, err := storage.DownloadFile(ctx, s3Key)
	if err != nil {
		t.Fatalf("Failed to download analysis result: %v", err)
	}

	var downloadedResult AnalysisResult
	if err := json.Unmarshal(downloaded, &downloadedResult); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if downloadedResult.AnalysisID != "analysis-abc-123" {
		t.Errorf("AnalysisID mismatch: got %s", downloadedResult.AnalysisID)
	}
	if len(downloadedResult.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(downloadedResult.Findings))
	}
	if downloadedResult.Findings[0].RuleID != "DTI-002" {
		t.Errorf("RuleID mismatch: got %s", downloadedResult.Findings[0].RuleID)
	}

	t.Logf("Successfully uploaded and downloaded analysis result via LocalStack S3")
}
