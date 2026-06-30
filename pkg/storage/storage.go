package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base directory: %w", err)
	}
	return &LocalStorage{BaseDir: abs}, nil
}

// safePath joins bucket/key under BaseDir and guarantees the result cannot
// escape BaseDir via "../" segments or absolute paths (path traversal defense).
func (s *LocalStorage) safePath(bucket, key string) (string, error) {
	joined := filepath.Join(s.BaseDir, filepath.Join("/", bucket, key))
	clean := filepath.Clean(joined)
	rel, err := filepath.Rel(s.BaseDir, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid path: bucket/key escapes storage root")
	}
	return clean, nil
}

func (s *LocalStorage) Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error) {
	destPath, err := s.safePath(bucket, key)
	if err != nil {
		return "", err
	}

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
	filePath, err := s.safePath(bucket, key)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	return file, nil
}

func (s *LocalStorage) Delete(ctx context.Context, bucket, key string) error {
	filePath, err := s.safePath(bucket, key)
	if err != nil {
		return err
	}
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}
