package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"fides/pkg/cosignverify"

	"github.com/google/uuid"
)

func recordingTestSpool(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "queue")
	t.Setenv("FIDES_SPOOL_DIR", path)
	return path
}

func TestRecordingReplayLostAcknowledgment(t *testing.T) {
	queue := recordingTestSpool(t)
	trailID, attestationID := uuid.New(), uuid.New()
	digest := strings.Repeat("a", 64)
	report := []byte("exact report\x00\x01\xff\r\n" + offlinePrefix + uuid.NewString())

	var mu sync.Mutex
	var paths []string
	var originalKey, originalBody string
	var trailAttempts int
	failArtifact := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		key := r.Header.Get("Idempotency-Key")
		if !validRecordingUUID(key) || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("recording request missing operation UUID or authorization")
		}
		switch r.URL.Path {
		case trailRecord:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			trailAttempts++
			if trailAttempts == 1 {
				originalKey, originalBody = key, string(body)
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
			if key != originalKey || string(body) != originalBody {
				t.Error("retry changed trail operation UUID or request body")
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%q}`, trailID)
		case artifactRecord:
			var fields struct {
				Trail string `json:"trail_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&fields); err != nil || fields.Trail != trailID.String() {
				t.Errorf("artifact trail = %q, %v", fields.Trail, err)
			}
			if failArtifact {
				http.Error(w, "fixture rejected artifact", http.StatusBadRequest)
				failArtifact = false
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"sha256":%q}`, digest)
		case attestationRecord:
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Error(err)
				return
			}
			form, err := multipart.NewReader(r.Body, params["boundary"]).ReadForm(1 << 20)
			if err != nil {
				t.Error(err)
				return
			}
			defer form.RemoveAll()
			if !reflect.DeepEqual(form.Value["trail_id"], []string{trailID.String()}) ||
				!reflect.DeepEqual(form.Value["payload"], []string{`{"verified":true}`}) {
				t.Errorf("unexpected form values %v", form.Value)
			}
			files := form.File["attachments"]
			if len(files) != 1 || files[0].Filename != "report.bin" {
				t.Errorf("unexpected attachments: %v", files)
				return
			}
			f, err := files[0].Open()
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			data, err := io.ReadAll(f)
			if err != nil || !bytes.Equal(data, report) {
				t.Errorf("attachment changed: %q, %v", data, err)
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%q}`, attestationID)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	config := cfg(srv)
	config.FailOpen = true
	body, err := recordJSON(config, trailRecord, map[string]any{"flow_id": uuid.NewString(), "name": "build"}, "")
	var trail struct{ ID string }
	if err != nil || json.Unmarshal([]byte(body), &trail) != nil || !strings.HasPrefix(trail.ID, offlinePrefix) {
		t.Fatalf("expected queued trail, got %q, %v", body, err)
	}
	mu.Lock()
	key := originalKey
	mu.Unlock()
	if !strings.HasSuffix(trail.ID, key) {
		t.Fatalf("offline trail reference did not use original UUID: %s", trail.ID)
	}
	artifact := map[string]any{"trail_id": trail.ID, "sha256": digest, "name": "image"}
	if _, err := recordJSON(config, artifactRecord, artifact, trail.ID); err != nil {
		t.Fatal(err)
	}
	attachment := filepath.Join(t.TempDir(), "report.bin")
	if err := os.WriteFile(attachment, report, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := uploadMultipart(config, trail.ID, digest, "evidence", "fixture", `{"verified":true}`, []attestationAttachment{{path: attachment}}, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(attachment); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(queue)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("spool directory is not private: %v, %v", info, err)
	}
	files, err := os.ReadDir(queue)
	if err != nil || len(files) != 3 {
		t.Fatalf("queue files = %v, %v", files, err)
	}
	for _, f := range files {
		info, err := f.Info()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("queue entry is not private: %v, %v", info, err)
		}
		raw, err := os.ReadFile(filepath.Join(queue, f.Name()))
		if err != nil || bytes.Contains(raw, []byte(config.Token)) || bytes.Contains(raw, []byte(srv.URL)) {
			t.Fatalf("queue stores endpoint or credential in plaintext: %v", err)
		}
	}

	wrong := config
	wrong.Token = "another-token"
	if n, err := replayRecordings(wrong); n != 0 || err == nil {
		t.Fatalf("wrong credential replayed %d, %v", n, err)
	}
	wrong = config
	wrong.ServerURL += "/wrong"
	if n, err := replayRecordings(wrong); n != 0 || err == nil {
		t.Fatalf("wrong endpoint replayed %d, %v", n, err)
	}
	if n, err := replayRecordings(config); n != 1 || err == nil || !strings.Contains(err.Error(), "still waiting") {
		t.Fatalf("expected only trail and retained dependents, replayed %d, %v", n, err)
	}
	if n, err := replayRecordings(config); n != 2 || err != nil {
		t.Fatalf("expected artifact and attestation, replayed %d, %v", n, err)
	}
	if n, err := replayRecordings(config); n != 0 || err != nil {
		t.Fatalf("expected empty queue, replayed %d, %v", n, err)
	}
	// The mapping is usable after previous dependents have all been removed.
	config.FailOpen = false
	if _, err := recordJSON(config, artifactRecord, artifact, trail.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{trailRecord, trailRecord, artifactRecord, artifactRecord, attestationRecord, artifactRecord}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("requests = %v, want %v", paths, want)
	}
}

func TestRecordingRejectsFinalErrors(t *testing.T) {
	queue := recordingTestSpool(t)
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer destination.Close()

	payload := map[string]any{"flow_id": uuid.NewString(), "name": "build"}
	for _, tc := range []struct {
		status int
		body   string
		queue  bool
	}{
		{http.StatusBadRequest, "", false},
		{http.StatusUnauthorized, "", false},
		{http.StatusForbidden, "", false},
		{http.StatusNotFound, "", false},
		{http.StatusConflict, "", false},
		{http.StatusTooManyRequests, "", false},
		{http.StatusTemporaryRedirect, "", false},
		{http.StatusPermanentRedirect, "", false},
		{http.StatusInternalServerError, "", false},
		{http.StatusServiceUnavailable, "API authentication is not configured on the server", false},
		{http.StatusServiceUnavailable, "service token tenant (FIDES_API_ORG_ID) is not configured", false},
		{http.StatusBadGateway, "", true},
		{http.StatusServiceUnavailable, "", true},
		{http.StatusGatewayTimeout, "", true},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.status, tc.body), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", destination.URL)
				http.Error(w, tc.body, tc.status)
			}))
			defer srv.Close()
			config := cfg(srv)
			config.FailOpen = true
			response, err := recordJSON(config, trailRecord, payload, "")
			if tc.queue != (err == nil && strings.Contains(response, `"queued":true`)) {
				t.Fatalf("expected queue=%v, got %q, %v", tc.queue, response, err)
			}
			if !tc.queue && err == nil {
				t.Fatalf("final failure returned success: %q", response)
			}
		})
	}
	if redirected.Load() {
		t.Fatal("recording followed a cross-origin redirect")
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS server got a recording")
	}))
	defer tlsServer.Close()
	for _, config := range []CLIConfig{
		{ServerURL: tlsServer.URL, Token: "test-token", FailOpen: true},
		{ServerURL: "http://localhost:99999", Token: "test-token", FailOpen: true},
		{ServerURL: "http://localhost:1", FailOpen: true},
	} {
		if response, err := recordJSON(config, trailRecord, payload, ""); err == nil {
			t.Fatalf("TLS or config failure returned success: %q", response)
		}
	}
	if files, err := os.ReadDir(queue); err != nil || len(files) != 3 {
		t.Fatalf("queued an ineligible failure: %v, %v", files, err)
	}

	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{syscall.ECONNREFUSED, true},
		{syscall.ECONNRESET, true},
		{io.ErrUnexpectedEOF, true},
		{&net.DNSError{IsTemporary: true}, true},
		{&net.DNSError{IsNotFound: true}, false},
		{syscall.EACCES, false},
		{errors.New("proxy authentication required"), false},
	} {
		if got := recordingTransportError(tc.err); got != tc.retry {
			t.Errorf("retryable(%v) = %v, want %v", tc.err, got, tc.retry)
		}
	}
}

func TestRecordingRejectsUnsafeSpool(t *testing.T) {
	queue := recordingTestSpool(t)
	dir := t.TempDir()
	payload := map[string]any{"flow_id": uuid.NewString(), "name": "build"}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	config := cfg(srv)
	config.FailOpen = true

	if err := os.Symlink(dir, queue); err != nil {
		t.Fatal(err)
	}
	if _, err := recordJSON(config, trailRecord, payload, ""); err == nil {
		t.Fatal("queued through a symlink")
	}
	if err := os.Remove(queue); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(queue, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := recordJSON(config, trailRecord, payload, ""); err == nil {
		t.Fatal("queued in an exposed spool")
	}
	if err := os.Chmod(queue, 0700); err != nil {
		t.Fatal(err)
	}
	response, err := recordJSON(config, trailRecord, payload, "")
	var saved struct{ ID string }
	if err != nil || json.Unmarshal([]byte(response), &saved) != nil || !strings.HasPrefix(saved.ID, offlinePrefix) {
		t.Fatalf("recording should queue in a private spool: %q, %v", response, err)
	}
	name := filepath.Join(queue, strings.TrimPrefix(saved.ID, offlinePrefix)+recordingSuffix)
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if count, err := replayRecordings(config); count != 0 || err == nil {
		t.Fatalf("replayed exposed entry: %d, %v", count, err)
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "good")
	if err := os.Link(name, backup); err != nil {
		t.Fatal(err)
	}
	if count, err := replayRecordings(config); count != 0 || err == nil {
		t.Fatalf("replayed hard-linked entry: %d, %v", count, err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, name); err != nil {
		t.Fatal(err)
	}
	if count, err := replayRecordings(config); count != 0 || err == nil {
		t.Fatalf("replayed symlink entry: %d, %v", count, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("unsafe entry reached the server: %d requests", calls.Load())
	}
}

func TestRecordingConcurrentReplayKeepsUnconfirmed(t *testing.T) {
	queue := recordingTestSpool(t)
	id := uuid.New()
	var mu sync.Mutex
	var originalBody, originalKey, originalContentType string
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		key := r.Header.Get("Idempotency-Key")
		contentType := r.Header.Get("Content-Type")
		mu.Lock()
		defer mu.Unlock()
		attempt := attempts.Add(1)
		if attempt == 1 {
			originalBody, originalKey, originalContentType = string(data), key, contentType
		} else if string(data) != originalBody || key != originalKey || contentType != originalContentType {
			t.Error("replay changed multipart bytes, content type or operation UUID")
		}
		switch attempt {
		case 1:
			http.Error(w, "unavailable", http.StatusBadGateway)
		case 2:
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%q}`, id)
		}
	}))
	defer srv.Close()
	config := cfg(srv)
	config.FailOpen = true
	knownTrail := uuid.NewString()
	if _, err := uploadMultipart(config, knownTrail, "", "test", "custom", `{}`, nil, false); err != nil {
		t.Fatal(err)
	}
	if count, err := replayRecordings(config); count != 0 || err == nil {
		t.Fatalf("discarded unconfirmed recording: %d, %v", count, err)
	}
	// A crash can leave a temporary write that was never published.
	if err := os.WriteFile(filepath.Join(queue, "."+uuid.NewString()+".tmp"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}

	type result struct {
		count int
		err   error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() {
			n, err := replayRecordings(config)
			done <- result{n, err}
		}()
	}
	var replayed int
	for range 2 {
		res := <-done
		if res.err != nil {
			t.Fatal(res.err)
		}
		replayed += res.count
	}
	if replayed != 1 || attempts.Load() != 3 {
		t.Fatalf("concurrent replay sent duplicate requests: %d replayed, %d attempts", replayed, attempts.Load())
	}
}

func TestRecordingFlagAndGateExit(t *testing.T) {
	if os.Getenv("FIDES_TEST_RECORDING_MAIN") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append(os.Args[:1], os.Args[i+1:]...)
				main()
				os.Exit(0)
			}
		}
		t.Fatal("missing test command")
	}
	recordingTestSpool(t)
	t.Setenv("FIDES_TEST_RECORDING_MAIN", "1")
	t.Setenv("FIDES_ENCRYPTION_KEY", "")
	t.Setenv("FIDES_API_TOKEN", "test-token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv("FIDES_SERVER_URL", srv.URL)
	run := func(args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), os.Args[0], append([]string{"-test.run=^TestRecordingFlagAndGateExit$", "--"}, args...)...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		return strings.TrimSpace(string(out)), stderr.String(), code
	}
	args := []string{"trail", "start", "--flow", uuid.NewString(), "--trail", "build", "--quiet"}
	t.Setenv("FIDES_FAIL_OPEN", "")
	if out, warning, code := run(append(args, "--fail-open")...); code != 0 || !strings.HasPrefix(out, offlinePrefix) ||
		!validRecordingUUID(strings.TrimPrefix(out, offlinePrefix)) || !strings.Contains(warning, "Evidence queued locally") {
		t.Fatalf("explicit fail-open exit=%d, stdout=%q, stderr=%q", code, out, warning)
	}
	t.Setenv("FIDES_FAIL_OPEN", "true")
	if out, warning, code := run(args...); code != 0 || !strings.HasPrefix(out, offlinePrefix) || !strings.Contains(warning, "Evidence queued locally") {
		t.Fatalf("environment fail-open exit=%d, stdout=%q, stderr=%q", code, out, warning)
	}
	if _, _, code := run(append(args, "--fail-open=false")...); code != 1 {
		t.Fatalf("explicitly disabled flag exited %d", code)
	}
	if _, _, code := run("assert", "--sha256", strings.Repeat("a", 64)); code != 1 {
		t.Fatalf("gate exit = %d", code)
	}
	if _, warning, code := run("attest", "--trail", uuid.NewString(), "--name", "test", "--type", "custom", "--payload", "{"); code != 1 ||
		strings.Contains(warning, "Evidence queued locally") {
		t.Fatal("malformed attestation payload passed or was queued")
	}
}

func TestRecordingVerifyImageKeepsGateExit(t *testing.T) {
	queue := recordingTestSpool(t)
	t.Setenv("FIDES_FAIL_OPEN", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	args := []string{"--sha256", strings.Repeat("a", 64), "--signer", "user@example.com", "--trail", uuid.NewString()}
	for _, tc := range []struct {
		verified bool
		exit     int
	}{{true, exitError}, {false, exitVerifyFailed}} {
		verifier := &mockVerifier{verdict: &cosignverify.Verdict{Verified: tc.verified}}
		if code := runVerifyImage(cfg(srv), verifier, io.Discard, args); code != tc.exit {
			t.Errorf("verify-image with verified=%v exited %d, want %d", tc.verified, code, tc.exit)
		}
	}
	if _, err := os.Stat(queue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verify-image touched the spool: %v", err)
	}
}
