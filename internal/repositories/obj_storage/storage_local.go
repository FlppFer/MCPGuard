package obj_storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	defaultLocalStackEndpoint = "http://localhost:4566"
	defaultLocalStackRegion   = "us-east-1"
	envLocalStackEndpoint     = "LOCALSTACK_ENDPOINT"
)

// LocalStackStorage wraps S3Storage for use with an externally-running LocalStack container.
type LocalStackStorage struct {
	*S3Storage
	bucket   string
	endpoint string
}

// NewLocalStorage connects to an already-running LocalStack container and creates the bucket if needed.
// The LocalStack endpoint defaults to http://localhost:4566 but can be overridden with LOCALSTACK_ENDPOINT.
func NewLocalStorage(bucket string) (*LocalStackStorage, error) {
	ctx := context.Background()

	endpoint := os.Getenv(envLocalStackEndpoint)
	if endpoint == "" {
		endpoint = defaultLocalStackEndpoint
	}

	slog.Info("Connecting to external LocalStack", "endpoint", endpoint, "bucket", bucket)

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(defaultLocalStackRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for LocalStack: %w", err)
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})

	// Create the bucket (ignore error if it already exists)
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		slog.Warn("Bucket creation failed (may already exist)", "bucket", bucket, "error", err)
	}

	s3Storage, err := NewS3Storage(ctx, bucket, endpoint, defaultLocalStackRegion, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3Storage for LocalStack: %w", err)
	}

	slog.Info("LocalStack S3 storage ready", "endpoint", endpoint, "bucket", bucket)

	return &LocalStackStorage{
		S3Storage: s3Storage,
		bucket:    bucket,
		endpoint:  endpoint,
	}, nil
}

// Endpoint returns the LocalStack S3 endpoint URL.
func (l *LocalStackStorage) Endpoint() string {
	return l.endpoint
}
