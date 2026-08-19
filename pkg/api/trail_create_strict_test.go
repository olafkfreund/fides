package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The exact payload a CI pipeline sent for months. It was answered 201 with the
// git metadata silently discarded — 316 trails, no error anywhere. It must now
// be refused, and the refusal must name the right field.
func TestCreateTrailRejectsTheBareGitFieldNames(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	flow := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'svc')`, flow, mine)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	body := `{"flow_id":"` + flow.String() + `","name":"b","commit":"abc","repository":"https://github.com/o/r","branch":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trails", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleCreateTrail(rec, req)

	got := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, got)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown fields, got %d: %s", rec.Code, got)
	}
	// The error has to be actionable — the whole failure was that nobody could
	// tell anything was wrong.
	for _, want := range []string{"commit", "git_commit"} {
		if !strings.Contains(got, want) {
			t.Errorf("the error must name %q so the caller can fix it; got: %s", want, got)
		}
	}
	// And nothing may be created.
	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM trails WHERE flow_id=$1`, flow).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a rejected payload must not create a trail, got %d", n)
	}
}

// Every first-party client's payload shape must keep working: the CLI, the
// model-provenance builder, and Fides' own CI all send the git_* names.
func TestCreateTrailAcceptsEveryFirstPartyPayload(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	flow := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'svc')`, flow, mine)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	for _, tc := range []struct{ name, body string }{
		{"minimal (dast-baseline-qa.sh)", `{"flow_id":"%F","name":"t1"}`},
		{"CI (go-build.yml)", `{"flow_id":"%F","name":"t2","git_commit":"abc","git_repository":"https://github.com/o/r"}`},
		{"CLI trail open", `{"flow_id":"%F","name":"t3","git_repository":"r","git_commit":"c","git_branch":"b","git_message":"m","git_committed_at":"","tags":{"committer":"a@b.c"}}`},
		{"model provenance", `{"flow_id":"%F","name":"t4","git_repository":"r","git_commit":"c","git_branch":"b","git_message":"","tags":{"framework":"pytorch"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.ReplaceAll(tc.body, "%F", flow.String())
			req := httptest.NewRequest(http.MethodPost, "/api/v1/trails", strings.NewReader(body))
			req = req.WithContext(principalCtx(mine))
			rec := httptest.NewRecorder()
			srv.handleCreateTrail(rec, req)
			if rec.Code != http.StatusCreated {
				t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The git metadata must actually land — a 201 alone was never proof.
func TestCreateTrailPersistsTheGitMetadata(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	flow := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'svc')`, flow, mine)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	body := `{"flow_id":"` + flow.String() + `","name":"persisted","git_repository":"https://github.com/o/r","git_commit":"deadbeef","git_branch":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trails", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleCreateTrail(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var repo, commit, branch string
	if err := pool.QueryRow(
		`SELECT coalesce(git_repository,''), coalesce(git_commit,''), coalesce(git_branch,'') FROM trails WHERE flow_id=$1 AND name='persisted'`,
		flow).Scan(&repo, &commit, &branch); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if repo == "" || commit == "" || branch == "" {
		t.Fatalf("git metadata was dropped: repo=%q commit=%q branch=%q", repo, commit, branch)
	}
}
