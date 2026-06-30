package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type StorageBackend interface {
	Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error)
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, bucket, key string) error
}

// LocalStorage implements StorageBackend for the local filesystem
type LocalStorage struct {
	BaseDir string
}

func NewLocalStorage(baseDir string) (*LocalStorage, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}
	return &LocalStorage{BaseDir: baseDir}, nil
}

func (s *LocalStorage) Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error) {
	destDir := filepath.Join(s.BaseDir, bucket)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bucket directory: %w", err)
	}

	destPath := filepath.Join(destDir, key)
	// Create subdirectories inside the bucket if key contains slashes
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create key subdirectories: %w", err)
	}

	file, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, r); err != nil {
		return "", fmt.Errorf("failed to write file content: %w", err)
	}

	// Return a URI representing the local path
	return fmt.Sprintf("local://%s/%s", bucket, key), nil
}

func (s *LocalStorage) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	filePath := filepath.Join(s.BaseDir, bucket, key)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	return file, nil
}

func (s *LocalStorage) Delete(ctx context.Context, bucket, key string) error {
	filePath := filepath.Join(s.BaseDir, bucket, key)
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}
