package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"fides/pkg/storage"
)

func TestRecordingReplayEndToEndIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	local, err := storage.NewLocalStorage(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	f.server.Storage = local
	t.Setenv("FIDES_FAIL_OPEN", "true")
	t.Setenv("FIDES_SPOOL_DIR", filepath.Join(root, "queue"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("AWS_S3_BUCKET", "fixture-evidence")
	t.Setenv("FIDES_ENCRYPTION_KEY", "")

	var disconnected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/compliance" {
			http.Error(w, "fixture unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.Method == http.MethodPost && req.URL.Path == "/api/v1/trails" && disconnected.CompareAndSwap(false, true) {
			// Commit the record, then drop only its response.
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusCreated {
				t.Errorf("initial recording returned HTTP %d: %s", rec.Code, rec.Body.String())
				w.WriteHeader(rec.Code)
				return
			}
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		f.handler.ServeHTTP(w, req)
	}))
	t.Cleanup(server.Close)
	t.Setenv("FIDES_SERVER_URL", server.URL)

	binary := filepath.Join(root, "fides")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/cli")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	run := func(args ...string) (stdout, stderr string, err error) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		var stderrBuffer strings.Builder
		cmd.Stderr = &stderrBuffer
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), stderrBuffer.String(), err
	}

	ref, stderr, err := run("trail", "start", "--flow", f.own["flow"], "--trail", "queued-build", "--quiet")
	if err != nil || !strings.HasPrefix(ref, "offline:") || stderr == "" {
		t.Fatalf("expected queued trail: stdout %q, stderr %q, err %v", ref, stderr, err)
	}
	sha := strings.Repeat("a", 64)
	if out, stderr, err := run("artifact", "report", "--org", f.own["org"], "--trail", ref, "--sha256", sha, "--name", "queued-image", "--type", "docker"); err != nil || stderr == "" {
		t.Fatalf("expected queued artifact: %q, %q, %v", out, stderr, err)
	}
	attachment := filepath.Join(root, "report.txt")
	const report = "fixture attachment\n"
	if err := os.WriteFile(attachment, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}
	if out, stderr, err := run("attest", "--trail", ref, "--artifact-sha", sha, "--name", "queued-evidence", "--type", "fixture", "--payload", "{}", "--attachments", attachment); err != nil || stderr == "" {
		t.Fatalf("expected queued attestation: %q, %q, %v", out, stderr, err)
	}
	if err := os.Remove(attachment); err != nil {
		t.Fatal(err)
	}
	if out, stderr, err := run("assert", "--sha256", sha); err == nil {
		t.Fatalf("unavailable gate succeeded: %q, %q", out, stderr)
	}

	for range 2 {
		if out, stderr, err := run("replay"); err != nil {
			t.Fatalf("replay: %q, %q, %v", out, stderr, err)
		}
	}
	var trailCount, artifactCount, attestationCount, attachmentCount int
	var location string
	err = f.pool.QueryRow(`SELECT
		(SELECT count(*) FROM trails WHERE flow_id=$1 AND name='queued-build'),
		(SELECT count(*) FROM artifacts a JOIN trails t ON t.id=a.trail_id WHERE a.sha256=$2 AND t.name='queued-build'),
		(SELECT count(*) FROM attestations a JOIN trails t ON t.id=a.trail_id WHERE a.name='queued-evidence' AND t.name='queued-build'),
		(SELECT count(*) FROM evidence_attachments e JOIN attestations a ON a.id=e.attestation_id WHERE a.name='queued-evidence'),
		(SELECT COALESCE(min(e.storage_path),'') FROM evidence_attachments e JOIN attestations a ON a.id=e.attestation_id WHERE a.name='queued-evidence')`,
		f.own["flow"], sha).Scan(&trailCount, &artifactCount, &attestationCount, &attachmentCount, &location)
	if err != nil || trailCount != 1 || artifactCount != 1 || attestationCount != 1 || attachmentCount != 1 {
		t.Fatalf("unexpected replay counts: %d %d %d %d, %v", trailCount, artifactCount, attestationCount, attachmentCount, err)
	}
	uri, err := url.Parse(location)
	if err != nil || uri.Scheme != "local" {
		t.Fatalf("attachment storage path: %q, %v", location, err)
	}
	r, err := local.Download(t.Context(), uri.Host, strings.TrimPrefix(uri.Path, "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil || string(body) != report {
		t.Fatalf("attachment bytes = %q, %v", body, err)
	}

	// The queued request ID persisted the original successful response.
	var cached []byte
	err = f.pool.QueryRow(`SELECT response FROM recording_operations WHERE endpoint='/api/v1/trails' AND org_id=$1`, f.own["org"]).Scan(&cached)
	if err != nil || !json.Valid(cached) {
		t.Fatalf("missing committed trail response: %v", err)
	}
}
