package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) *LocalStorage {
	t.Helper()
	s, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}
	return s
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	uri, err := s.Upload(ctx, "fides-evidence", "att-1/report.txt", strings.NewReader("hello"), "text/plain")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if uri == "" {
		t.Fatalf("expected a non-empty URI")
	}

	rc, err := s.Download(ctx, "fides-evidence", "att-1/report.txt")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

// TestUploadRejectsPathTraversal is the regression test for H1: a malicious
// key must never write outside BaseDir.
func TestUploadRejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	s, err := NewLocalStorage(base)
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}
	ctx := context.Background()

	// Create a sentinel file one level above the storage root.
	parent := filepath.Dir(base)
	sentinel := filepath.Join(parent, "fides_traversal_sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	defer os.Remove(sentinel)

	// Attempt to overwrite the sentinel via a traversal key/bucket.
	for _, tc := range []struct{ bucket, key string }{
		{"fides-evidence", "../../fides_traversal_sentinel.txt"},
		{"../..", "fides_traversal_sentinel.txt"},
		{"fides-evidence", "../../../etc/cron.d/x"},
	} {
		_, _ = s.Upload(ctx, tc.bucket, tc.key, strings.NewReader("HACKED"), "text/plain")
	}

	// The sentinel outside BaseDir must be untouched.
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel read: %v", err)
	}
	if string(data) != "original" {
		t.Fatalf("path traversal escaped BaseDir: sentinel was overwritten")
	}
}

func TestSafePathStaysWithinBase(t *testing.T) {
	s := newStore(t)
	for _, key := range []string{"../../etc/passwd", "a/../../b", "/abs/path"} {
		p, err := s.safePath("bucket", key)
		if err != nil {
			continue // rejected outright is acceptable
		}
		rel, err := filepath.Rel(s.BaseDir, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Fatalf("safePath(%q) escaped BaseDir: %s", key, p)
		}
	}
}

func TestDeleteMissingIsNoError(t *testing.T) {
	s := newStore(t)
	if err := s.Delete(context.Background(), "fides-evidence", "nope.txt"); err != nil {
		t.Fatalf("deleting a missing file should be a no-op, got %v", err)
	}
}
