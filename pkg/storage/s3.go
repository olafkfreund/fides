package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Storage struct {
	Client *s3.Client
	Region string
}

func NewS3Storage(ctx context.Context, region string) (*S3Storage, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)
	return &S3Storage{
		Client: client,
		Region: cfg.Region,
	}, nil
}

func (s *S3Storage) Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error) {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        r,
		ContentType: aws.String(contentType),
	}

	_, err := s.Client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to upload object to S3: %w", err)
	}

	return fmt.Sprintf("s3://%s/%s", bucket, key), nil
}

func (s *S3Storage) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := s.Client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to download object from S3: %w", err)
	}

	return output.Body, nil
}

func (s *S3Storage) Delete(ctx context.Context, bucket, key string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := s.Client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete object from S3: %w", err)
	}

	return nil
}
