package obj_storage

import (
	"context"
	"fmt"
	"os"

	"github.com/FlppFer/MCPGuard/config"
)

type S3Storage struct {
	client *s3.Client
	bucket string
}

func NewS3Storage(bucket string, endpoint string, region string, forcePathStyle bool) (*S3Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						URL:               endpoint,
						HostnameImmutable: true,
						PartitionID:       "aws",
					}, nil
				},
			),
		),
	)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = forcePathStyle // required for MinIO
	})

	return &S3Storage{
		client: client,
		bucket: bucket,
	}, nil
}

func (s *S3Storage) UploadFile(ctx context.Context, key string, localPath string) error {
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()

	uploader := manager.NewUploader(s.client)

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   file,
	})

	return err
}

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

func (s *S3Storage) GetFileURL(key string) (string, error) {
	return fmt.Sprintf("%s/%s/%s", s.client.Endpoint, s.bucket, key), nil
}
