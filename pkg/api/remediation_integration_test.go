package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// TestRemediationLifecycleIntegration walks the full HTTP-level lifecycle:
// propose -> (cannot apply) -> approve (distinct approver) -> apply, and
// confirms the allowlist_entry domain actually performs its low-risk change.
// It also confirms self-approval and applying-without-approval are rejected.
func TestRemediationLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the remediation integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org, env := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, env, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	proposerCtx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "alice@example.com", Role: auth.RoleAdmin, Kind: "session"})
	approverCtx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "bob@example.com", Role: auth.RoleAdmin, Kind: "session"})
	sha := "deadbeef00112233"

	// propose an allowlist_entry remediation.
	rec := httptest.NewRecorder()
	body := `{"environment_id":"` + env.String() + `","domain":"allowlist_entry","reason":"shadow deploy needs approval","params":{"artifact_sha256":"` + sha + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remediation", strings.NewReader(body)).WithContext(proposerCtx)
	s.handleProposeRemediation(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var proposed struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &proposed); err != nil {
		t.Fatalf("decode propose response: %v", err)
	}

	// applying before approval must fail (the core safety invariant).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(proposerCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApplyRemediation(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("apply-before-approval: expected 409, got %d %s", rec.Code, rec.Body.String())
	}

	// self-approval must be rejected (segregation of duties).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(proposerCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApproveRemediation(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("self-approve: expected 409, got %d %s", rec.Code, rec.Body.String())
	}

	// approval by a distinct principal succeeds.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(approverCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApproveRemediation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	// apply now succeeds and performs the allowlist insert.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(proposerCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApplyRemediation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}

	var allowed bool
	if err := pool.QueryRow(`SELECT EXISTS(SELECT 1 FROM environment_allowlist WHERE environment_id=$1 AND artifact_sha256=$2)`, env, sha).Scan(&allowed); err != nil {
		t.Fatalf("query allowlist: %v", err)
	}
	if !allowed {
		t.Fatalf("expected apply to allow-list the digest")
	}

	// re-applying an already-applied action must fail.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(proposerCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApplyRemediation(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-apply: expected 409, got %d %s", rec.Code, rec.Body.String())
	}
}

// TestRemediationRejectIntegration confirms a rejected action can never be applied.
func TestRemediationRejectIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the remediation integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()

	org, env := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, env, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	proposerCtx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "carol@example.com", Role: auth.RoleAdmin, Kind: "session"})
	approverCtx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "dave@example.com", Role: auth.RoleAdmin, Kind: "session"})

	rec := httptest.NewRecorder()
	body := `{"environment_id":"` + env.String() + `","domain":"env_tag","reason":"mis-tagged","params":{"tags":{"pci-scope":"false"}}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remediation", strings.NewReader(body)).WithContext(proposerCtx)
	s.handleProposeRemediation(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var proposed struct {
		ID uuid.UUID `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &proposed)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(approverCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleRejectRemediation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(proposerCtx)
	req.SetPathValue("id", proposed.ID.String())
	s.handleApplyRemediation(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("apply-after-reject: expected 409, got %d %s", rec.Code, rec.Body.String())
	}
}
