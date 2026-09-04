package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Direct, cheap wins: hashFile, postRequest, uploadMultipart, printUsage.

func TestHashFileMatchesSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	content := []byte("fides-cli-coverage-fixture")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("hashFile = %s, want %s", got, want)
	}
}

func TestHashFileMissing(t *testing.T) {
	if _, err := hashFile(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestPrintUsageDoesNotPanic(t *testing.T) {
	printUsage()
}

func TestPostRequestSendsJSONAndAuth(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"trail-1"}`)
	body, err := postRequest(cfg(srv), "/api/v1/trails", map[string]any{"name": "release-42"})
	if err != nil {
		t.Fatalf("postRequest: %v", err)
	}
	if body != `{"id":"trail-1"}` {
		t.Errorf("body = %q", body)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if ct := got.raw; !strings.Contains(ct, "release-42") {
		t.Errorf("request body %q does not carry the payload", ct)
	}
}

func TestPostRequestReturnsErrorOnServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	t.Cleanup(srv.Close)

	_, err := postRequest(cfg(srv), "/api/v1/trails", map[string]any{})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error %q should carry the server body", err)
	}
}

// uploadMultipart is what carries an attestation payload and its attachments.
// Assert on the actual multipart body it produces, not just that it succeeds.
func TestUploadMultipartBodyCarriesFieldsAndAttachment(t *testing.T) {
	dir := t.TempDir()
	attachment := filepath.Join(dir, "report.json")
	if err := os.WriteFile(attachment, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotContentType, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"id":"att-1"}`)
	}))
	t.Cleanup(srv.Close)

	respBody, err := uploadMultipart(cfg(srv), "trail-1", "deadbeef", "snyk-scan", "snyk",
		`{"vulns":0}`, []string{attachment}, true)
	if err != nil {
		t.Fatalf("uploadMultipart: %v", err)
	}
	if respBody != `{"id":"att-1"}` {
		t.Errorf("respBody = %q", respBody)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if !strings.HasPrefix(gotContentType, "multipart/form-data") {
		t.Errorf("Content-Type = %q, want multipart/form-data", gotContentType)
	}

	raw := string(gotBody)
	for _, want := range []string{
		`name="trail_id"`, "trail-1",
		`name="artifact_sha256"`, "deadbeef",
		`name="name"`, "snyk-scan",
		`name="type_name"`, "snyk",
		`name="payload"`, `{"vulns":0}`,
		`name="encrypted"`, "true",
		`name="attachments"; filename="report.json"`, `{"ok":true}`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("multipart body does not contain %q\n--- body ---\n%s", want, raw)
		}
	}
}

func TestUploadMultipartNotEncrypted(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	_, err := uploadMultipart(cfg(srv), "trail-1", "", "n", "t", "p", nil, false)
	if err != nil {
		t.Fatalf("uploadMultipart: %v", err)
	}
	if !strings.Contains(got.raw, `name="encrypted"`) || !strings.Contains(got.raw, "false") {
		t.Errorf("expected encrypted=false in body, got %q", got.raw)
	}
}

func TestUploadMultipartMissingAttachmentErrors(t *testing.T) {
	srv, _ := recordingServer(t, `{}`)
	_, err := uploadMultipart(cfg(srv), "t", "", "n", "ty", "p", []string{"/no/such/file"}, false)
	if err == nil {
		t.Fatal("expected an error opening a missing attachment")
	}
}
