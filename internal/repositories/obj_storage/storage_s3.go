package obj_storage

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// customEndpointResolver implements aws.EndpointResolverWithOptions.
// It returns the provided endpoint URL for any service/region.
type customEndpointResolver struct {
	endpoint string
}

func (r customEndpointResolver) ResolveEndpoint(service, region string, options ...interface{}) (aws.Endpoint, error) {
	return aws.Endpoint{
		URL:               r.endpoint,
		SigningRegion:     region,
		HostnameImmutable: true,
	}, nil
}

type S3Storage struct {
	client   *s3.Client
	bucket   string
	endpoint string // keep original endpoint for URL generation
}

func NewS3Storage(ctx context.Context, bucket string, endpoint string, region string, forcePathStyle bool) (*S3Storage, error) {
	// Load default config but override endpoint resolver when a custom endpoint is provided.
	var cfg aws.Config
	var err error

	if endpoint != "" {
		cfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithEndpointResolverWithOptions(customEndpointResolver{endpoint: endpoint}),
		)
	} else {
		// Use normal resolution (AWS)
		cfg, err = awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	}
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = forcePathStyle // required for MinIO compatibility
		// o.Region already set from cfg
	})

	return &S3Storage{
		client:   client,
		bucket:   bucket,
		endpoint: endpoint,
	}, nil
}

// UploadFile uploads a local file to the configured bucket with the given key.
func (s *S3Storage) UploadFile(ctx context.Context, key string, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	uploader := manager.NewUploader(s.client)

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	return err
}

// DownloadFile downloads the object and returns its bytes.
func (s *S3Storage) DownloadFile(ctx context.Context, key string) ([]byte, error) {
	downloader := manager.NewDownloader(s.client)

	buf := manager.NewWriteAtBuffer([]byte{})

	_, err := downloader.Download(ctx, buf, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// StreamDownloadTo writes the object directly to an io.Writer (useful to stream to a file).
func (s *S3Storage) StreamDownloadTo(ctx context.Context, key string, w io.WriterAt) error {
	downloader := manager.NewDownloader(s.client)
	_, err := downloader.Download(ctx, w, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	return err
}

// GetFileURL returns a best-effort public URL for the object. For S3-like endpoints we build it.
// Note: For real presigned URLs you should use s3.PresignGetObject with a signer.
func (s *S3Storage) GetFileURL(key string) (string, error) {
	if s.endpoint != "" {
		// endpoint is expected to include scheme e.g. "https://play.min.io"
		return fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucket, key), nil
	}
	// Fallback to AWS S3 host using the client's region (best-effort)
	// client.EndpointResolver is not exported for URL build, so construct generic S3 URL:
	return fmt.Sprintf("https://%s.s3.amazonaws.com/%s", s.bucket, key), nil
}
