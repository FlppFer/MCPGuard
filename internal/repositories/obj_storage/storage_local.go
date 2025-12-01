package obj_storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/elgohr/go-localstack"
)

// LocalStackStorage wraps S3Storage with a LocalStack instance for local development
type LocalStackStorage struct {
	*S3Storage
	instance *localstack.Instance
	bucket   string
}

const (
	LocalStackErrorMessage = "Failed to create LocalStack instance"
)

// NewLocalStorage creates a LocalStack-backed S3 storage for local development.
// It starts a LocalStack Docker container and creates the specified bucket.
func NewLocalStorage(bucket string) (*LocalStackStorage, error) {
	ctx := context.Background()

	instance, err := localstack.NewInstance()
	if err != nil {
		slog.Error(LocalStackErrorMessage, "error", err)
		return nil, fmt.Errorf("%s: %w", LocalStackErrorMessage, err)
	}

	if err := instance.Start(); err != nil {
		slog.Error("Failed to start LocalStack", "error", err)
		return nil, fmt.Errorf("%s: %w", LocalStackErrorMessage, err)
	}

	endpoint := instance.EndpointV2(localstack.S3)
	slog.Info("LocalStack S3 started", "endpoint", endpoint, "bucket", bucket)

	// Create S3 client for bucket creation
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		instance.Stop()
		slog.Error("Failed to load AWS config", "error", err)
		return nil, fmt.Errorf("%s: %w", LocalStackErrorMessage, err)
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})

	// Create the bucket
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		slog.Warn("Bucket creation failed (may already exist)", "bucket", bucket, "error", err)
	}

	// Create S3Storage pointing to LocalStack
	s3Storage, err := NewS3Storage(ctx, bucket, endpoint, "us-east-1", true)
	if err != nil {
		instance.Stop()
		slog.Error("Failed to create S3Storage", "error", err)
		return nil, fmt.Errorf("%s: %w", LocalStackErrorMessage, err)
	}

	return &LocalStackStorage{
		S3Storage: s3Storage,
		instance:  instance,
		bucket:    bucket,
	}, nil
}

// Stop gracefully shuts down the LocalStack container
func (l *LocalStackStorage) Stop() error {
	if l.instance != nil {
		slog.Info("Stopping LocalStack instance")
		return l.instance.Stop()
	}
	return nil
}

// Endpoint returns the LocalStack S3 endpoint URL
func (l *LocalStackStorage) Endpoint() string {
	if l.instance != nil {
		return l.instance.EndpointV2(localstack.S3)
	}
	return ""
}
