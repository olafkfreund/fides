package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3API is the subset of the S3 client used here (allows mocking in tests).
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3Storage struct {
	Client s3API
	Region string
	// WORM / retention: when RetentionMode is set (GOVERNANCE or COMPLIANCE) and
	// RetentionDays > 0, every uploaded object is written with an S3 Object Lock
	// retain-until date, making evidence immutable for the retention window
	// (required for DORA/SOX). The bucket must have Object Lock enabled.
	RetentionMode types.ObjectLockMode
	RetentionDays int
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

	s := &S3Storage{Client: s3.NewFromConfig(cfg), Region: cfg.Region}
	switch os.Getenv("FIDES_OBJECT_LOCK_MODE") {
	case "GOVERNANCE":
		s.RetentionMode = types.ObjectLockModeGovernance
	case "COMPLIANCE":
		s.RetentionMode = types.ObjectLockModeCompliance
	}
	if d, err := strconv.Atoi(os.Getenv("FIDES_EVIDENCE_RETENTION_DAYS")); err == nil && d > 0 {
		s.RetentionDays = d
	}
	return s, nil
}

func (s *S3Storage) Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error) {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        r,
		ContentType: aws.String(contentType),
	}
	// WORM: pin an Object Lock retain-until date so the evidence cannot be
	// deleted or overwritten before it expires.
	if s.RetentionMode != "" && s.RetentionDays > 0 {
		input.ObjectLockMode = s.RetentionMode
		input.ObjectLockRetainUntilDate = aws.Time(time.Now().UTC().AddDate(0, 0, s.RetentionDays))
	}

	if _, err := s.Client.PutObject(ctx, input); err != nil {
		return "", fmt.Errorf("failed to upload object to S3: %w", err)
	}

	return fmt.Sprintf("s3://%s/%s", bucket, key), nil
}

func (s *S3Storage) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	output, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from S3: %w", err)
	}
	return output.Body, nil
}

func (s *S3Storage) Delete(ctx context.Context, bucket, key string) error {
	if _, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("failed to delete object from S3: %w", err)
	}
	return nil
}
