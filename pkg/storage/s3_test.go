package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type mockS3 struct{ last *s3.PutObjectInput }

func (m *mockS3) PutObject(ctx context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.last = in
	return &s3.PutObjectOutput{}, nil
}
func (m *mockS3) GetObject(ctx context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{}, nil
}
func (m *mockS3) DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil
}

func TestS3UploadSetsObjectLockRetention(t *testing.T) {
	m := &mockS3{}
	s := &S3Storage{Client: m, RetentionMode: types.ObjectLockModeCompliance, RetentionDays: 30}
	if _, err := s.Upload(context.Background(), "b", "k", strings.NewReader("data"), "text/plain"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if m.last.ObjectLockMode != types.ObjectLockModeCompliance {
		t.Fatalf("expected COMPLIANCE lock, got %q", m.last.ObjectLockMode)
	}
	if m.last.ObjectLockRetainUntilDate == nil {
		t.Fatal("expected a retain-until date")
	}
	d := time.Until(*m.last.ObjectLockRetainUntilDate)
	if d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("retain-until not ~30 days out: %v", d)
	}
}

func TestS3UploadNoRetentionByDefault(t *testing.T) {
	m := &mockS3{}
	s := &S3Storage{Client: m}
	if _, err := s.Upload(context.Background(), "b", "k", strings.NewReader("x"), "text/plain"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if m.last.ObjectLockMode != "" || m.last.ObjectLockRetainUntilDate != nil {
		t.Fatal("expected no Object Lock when retention is unset")
	}
}
