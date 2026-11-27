package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fides/pkg/auth"
	"fides/pkg/db"
	"fides/pkg/models"
	"fides/pkg/storage"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func postRecording(handler http.Handler, path, key, contentType string, body io.Reader, credential routeCredential) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if credential != nil {
		credential(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func expectRecording(t *testing.T, rec *httptest.ResponseRecorder, status int) string {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("HTTP %d, want %d: %s", rec.Code, status, rec.Body)
	}
	return rec.Body.String()
}

func assertRecordingCount(t *testing.T, f *routeAuthFixture, want int, query string, args ...any) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(query, args...).Scan(&count); err != nil || count != want {
		t.Fatalf("%s: count = %d, want %d, err = %v", query, count, want, err)
	}
}

func TestRecordingIdempotencyIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	if err := db.ApplyRLS(t.Context(), f.pool); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIDES_RLS_ENABLED", "true")
	writer := f.sessions[auth.RoleWriter]
	trail := fmt.Sprintf(`{"flow_id":%q,"name":"replayed"}`, f.own["flow"])
	artifact := fmt.Sprintf(`{"trail_id":%q,"sha256":%q,"name":"synthetic","type":"file"}`, f.own["trail"], strings.Repeat("d", 64))
	const trails, artifacts = "/api/v1/trails", "/api/v1/artifacts"
	post := func(endpoint, key, body string, credential routeCredential) *httptest.ResponseRecorder {
		return postRecording(f.handler, endpoint, key, "application/json", strings.NewReader(body), credential)
	}
	key := uuid.NewString()
	expectRecording(t, post(trails, key, trail, nil), http.StatusUnauthorized)
	expectRecording(t, post(trails, key, trail, f.sessions[auth.RoleViewer]), http.StatusForbidden)
	expectRecording(t, post(trails, "invalid-key", trail, writer), http.StatusBadRequest)
	expectRecording(t, post(trails, key, fmt.Sprintf(`{"flow_id":%q,"name":"replayed"}`, f.other["flow"]), writer), http.StatusNotFound)

	// The first response is discarded as if its acknowledgement was lost.
	first := expectRecording(t, post(trails, key, trail, writer), http.StatusCreated)
	replay := expectRecording(t, post(trails, key, trail, writer), http.StatusCreated)
	if first != replay {
		t.Fatalf("replay changed response: %s != %s", first, replay)
	}
	expectRecording(t, post(trails, key, strings.ReplaceAll(trail, "replayed", "changed"), writer), http.StatusConflict)
	expectRecording(t, post(artifacts, key, artifact, writer), http.StatusConflict)
	failedKey := uuid.NewString()
	expectRecording(t, post(trails, failedKey, trail, writer), http.StatusConflict)
	expectRecording(t, post(trails, failedKey, strings.ReplaceAll(trail, "replayed", "new"), writer), http.StatusCreated)
	expectRecording(t, post(trails, key, trail, f.sessions[auth.RoleViewer]), http.StatusForbidden)
	expectRecording(t, post(trails, key, trail, nil), http.StatusUnauthorized)

	other := routeSession(t, f.server, f.other["org"], auth.RoleWriter, time.Hour)
	expectRecording(t, post(trails, key, trail, other), http.StatusNotFound)
	expectRecording(t, post(trails, key, strings.ReplaceAll(trail, f.own["flow"], f.other["flow"]), other), http.StatusCreated)

	artifactKey := uuid.NewString()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 6)
	for range cap(results) {
		go func() {
			<-start
			results <- post(artifacts, artifactKey, artifact, writer)
		}()
	}
	close(start)
	first = ""
	for range cap(results) {
		body := expectRecording(t, <-results, http.StatusCreated)
		if first != "" && body != first {
			t.Fatalf("concurrent replay changed response: %s != %s", first, body)
		}
		first = body
	}
	assertRecordingCount(t, f, 2, `SELECT count(*) FROM trails WHERE name = 'replayed'`)
	assertRecordingCount(t, f, 4, `SELECT count(*) FROM recording_operations`)
	assertRecordingCount(t, f, 1, `SELECT count(*) FROM artifacts WHERE sha256 = $1`, strings.Repeat("d", 64))
	assertRecordingCount(t, f, 1, `SELECT count(*) FROM integration_events`)

	// Failure to save the result must roll back both the write and its outbox event.
	cacheFailureKey := uuid.NewString()
	mustExec(t, f.pool, `ALTER TABLE recording_operations ADD CONSTRAINT fixture_fail_cache
		CHECK (operation_id <> `+pq.QuoteLiteral(cacheFailureKey)+`)`)
	failedArtifact := strings.ReplaceAll(artifact, strings.Repeat("d", 64), strings.Repeat("c", 64))
	expectRecording(t, post(artifacts, cacheFailureKey, failedArtifact, writer), http.StatusInternalServerError)
	assertRecordingCount(t, f, 0, `SELECT count(*) FROM artifacts WHERE sha256 = $1`, strings.Repeat("c", 64))
	assertRecordingCount(t, f, 1, `SELECT count(*) FROM integration_events`)

	// The application predicates and the RLS policy enforce tenant scope independently.
	var schema string
	if err := f.pool.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := pq.QuoteIdentifier("recording_" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	tx, err := f.pool.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		"CREATE ROLE " + role + " NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + pq.QuoteIdentifier(schema) + " TO " + role,
		"GRANT SELECT, INSERT ON recording_operations TO " + role,
		"SET LOCAL ROLE " + role,
	} {
		if _, err := tx.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	var visible int
	if err := tx.QueryRow(`SELECT count(*) FROM recording_operations`).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("unscoped role sees %d operations, err = %v", visible, err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_org', $1, true)`, f.other["org"]); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT count(*) FROM recording_operations`).Scan(&visible); err != nil || visible != 1 {
		t.Fatalf("other tenant sees %d operations, err = %v", visible, err)
	}
	_, err = tx.Exec(`INSERT INTO recording_operations (org_id, operation_id, endpoint, fingerprint, response)
		VALUES ($1, $2, $3, $4, $5)`, f.own["org"], uuid.New(), trails, make([]byte, 32), []byte("{}"))
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("cross-tenant cache insert: %v", err)
	}
}

type interruptedRecordingStorage struct {
	storage.StorageBackend
	keys []string
	fail int
}

func (s *interruptedRecordingStorage) Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) (string, error) {
	s.keys = append(s.keys, key)
	if len(s.keys) == s.fail {
		return "", errors.New("synthetic upload failure")
	}
	return s.StorageBackend.Upload(ctx, bucket, key, reader, contentType)
}

func TestRecordingAttachmentsIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	t.Setenv("FIDES_EVENTS_ENABLED", "true")
	const bucket = "synthetic-recording"
	t.Setenv("AWS_S3_BUCKET", bucket)
	local, err := storage.NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &interruptedRecordingStorage{StorageBackend: local, fail: 2}
	f.server.Storage = store
	mustExec(t, f.pool, `INSERT INTO attestation_types (org_id,name,schema)
		VALUES ($1, 'synthetic-review', '{"properties":{"approved":{"type":"boolean"}}}')`, f.own["org"])

	key := uuid.NewString()
	post := func(second string) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for name, value := range map[string]string{
			"trail_id": f.own["trail"], "name": "synthetic-review", "type_name": "synthetic-review",
			"payload": `{"approved":"yes"}`, "signed_by": "synthetic-signer", "signature": "synthetic-signature",
			"signature_algorithm": "synthetic-algorithm", "manifestation_reason": "synthetic-approval",
		} {
			if err := form.WriteField(name, value); err != nil {
				t.Fatal(err)
			}
		}
		for _, data := range []string{"first attachment", second} {
			file, err := form.CreateFormFile("attachments", "same-name.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, data); err != nil {
				t.Fatal(err)
			}
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		return postRecording(f.handler, "/api/v1/attestations", key, form.FormDataContentType(), &body, f.sessions[auth.RoleWriter])
	}
	checkCounts := func(attestations, attachments int) {
		t.Helper()
		assertRecordingCount(t, f, attestations, `SELECT count(*) FROM attestations WHERE trail_id = $1 AND name = 'synthetic-review'`, f.own["trail"])
		assertRecordingCount(t, f, attestations, `SELECT count(*) FROM recording_operations WHERE operation_id = $1`, key)
		assertRecordingCount(t, f, attestations, `SELECT count(*) FROM integration_events WHERE event_type = 'compliance.evaluated'`)
		assertRecordingCount(t, f, attachments, `SELECT count(*) FROM evidence_attachments`)
	}

	const second = "second attachment"
	expectRecording(t, post(second), http.StatusInternalServerError)
	checkCounts(0, 0)
	mustExec(t, f.pool, `ALTER TABLE evidence_attachments ADD CONSTRAINT fixture_fail_attachment CHECK (file_size = -1)`)
	expectRecording(t, post(second), http.StatusInternalServerError)
	checkCounts(0, 0)
	mustExec(t, f.pool, `ALTER TABLE evidence_attachments DROP CONSTRAINT fixture_fail_attachment`)

	response := expectRecording(t, post(second), http.StatusCreated)
	replay := expectRecording(t, post(second), http.StatusCreated)
	if replay != response {
		t.Fatalf("replay changed response: %s != %s", replay, response)
	}
	expectRecording(t, post("changed attachment"), http.StatusConflict)
	checkCounts(1, 2)
	if len(store.keys) != 5 || store.keys[0] != store.keys[2] || store.keys[0] != store.keys[3] ||
		store.keys[1] != store.keys[4] || store.keys[0] == store.keys[1] {
		t.Fatalf("unexpected storage attempts: %v", store.keys)
	}

	var att models.Attestation
	if err := json.Unmarshal([]byte(response), &att); err != nil || att.IsCompliant ||
		len(att.ValidationErrors) != 1 || att.ValidationErrors[0].Code != "schema_validation_failed" {
		t.Fatalf("schema verdict changed: %s, %v", response, err)
	}
	assertRecordingCount(t, f, 1, `SELECT count(*) FROM attestations WHERE id = $1
		AND signed_by = 'synthetic-signer' AND signature = 'synthetic-signature'
		AND signature_algorithm = 'synthetic-algorithm' AND manifestation_reason = 'synthetic-approval'
		AND jsonb_array_length(validation_errors) = 1`, att.ID)
	ctx := auth.WithPrincipal(t.Context(), &auth.Principal{OrgID: uuid.MustParse(f.own["org"])})
	if verdict := verifyChain(t, f.server, ctx, uuid.MustParse(f.own["trail"])); !verdict.Valid || verdict.Count != 1 {
		t.Fatalf("invalid chain: %+v", verdict)
	}
	for i, want := range []string{"first attachment", second} {
		obj, err := local.Download(t.Context(), bucket, store.keys[i])
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(obj)
		obj.Close()
		if err != nil || string(body) != want {
			t.Fatalf("attachment %d = %q, want %q, err = %v", i, body, want, err)
		}
		assertRecordingCount(t, f, 1, `SELECT count(*) FROM evidence_attachments WHERE attestation_id = $1
			AND file_name = 'same-name.txt' AND file_size = $2 AND file_hash = $3 AND storage_path = $4`,
			att.ID, len(want), fmt.Sprintf("%x", sha256.Sum256([]byte(want))), "local://"+bucket+"/"+store.keys[i])
	}
}
