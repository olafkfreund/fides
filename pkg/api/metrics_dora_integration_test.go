package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// TestDoraMetricsLeadTimeAndMTTR checks the two DORA metrics added to the /dora
// endpoint: lead time for changes (trail -> deployment anchor) and MTTR
// (non-compliant deployment -> next compliant deployment of the same service).
func TestDoraMetricsLeadTimeAndMTTR(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the DORA metrics integration test")
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
	mig21, _ := os.ReadFile(filepath.Join("..", "db", "migrations", "0021_trail_committed_at.sql"))
	if _, err := pool.Exec(string(mig21)); err != nil {
		t.Fatalf("migration 0021: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	// Trail entered the pipeline 3h ago (git_committed_at left NULL here, so lead
	// time falls back to created_at).
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,created_at) VALUES ($1,$2,'t','abc123', now() - interval '3 hours')`, trail, flow)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	// Lead time: svc-a deployed 1h ago -> 2h lead (anchor -1h minus trail -3h).
	mustExec(t, pool, `INSERT INTO deployment_anchors (org_id,trail_id,ci_sys_id,ci_name,compliant,created_at)
		VALUES ($1,$2,'ci-a','svc-a',true, now() - interval '1 hour')`, org, trail)
	// MTTR: svc-b failed 5h ago (before the trail, excluded from lead time),
	// restored 2h ago -> 3h restore; the restored anchor also gives 1h lead.
	mustExec(t, pool, `INSERT INTO deployment_anchors (org_id,trail_id,ci_sys_id,ci_name,compliant,created_at)
		VALUES ($1,$2,'ci-b','svc-b',false, now() - interval '5 hours')`, org, trail)
	mustExec(t, pool, `INSERT INTO deployment_anchors (org_id,trail_id,ci_sys_id,ci_name,compliant,created_at)
		VALUES ($1,$2,'ci-b','svc-b',true, now() - interval '2 hours')`, org, trail)

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/dora?days=30", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleDoraMetrics(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dora: %d %s", rec.Code, rec.Body.String())
	}

	var out struct {
		LeadTimeHours *float64 `json:"lead_time_hours"`
		MTTRHours     *float64 `json:"mttr_hours"`
		Restored      int      `json:"mttr_restored_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Lead-time set is {2h (svc-a), 1h (svc-b restored anchor)} -> median 1.5h.
	if out.LeadTimeHours == nil || !approx(*out.LeadTimeHours, 1.5, 0.05) {
		t.Fatalf("lead_time_hours = %v, want ~1.5", out.LeadTimeHours)
	}
	// svc-b failed -> restored after 3h.
	if out.MTTRHours == nil || !approx(*out.MTTRHours, 3.0, 0.05) {
		t.Fatalf("mttr_hours = %v, want ~3.0", out.MTTRHours)
	}
	if out.Restored != 1 {
		t.Fatalf("mttr_restored_count = %d, want 1", out.Restored)
	}
}

func approx(a, b, tol float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// TestDoraLeadTimeUsesCommitTimestamp verifies lead time is measured from the
// git commit timestamp (git_committed_at) when present, not the trail's
// creation time — i.e. true code-to-prod lead time (#301).
func TestDoraLeadTimeUsesCommitTimestamp(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the DORA commit-timestamp test")
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
	mig21, _ := os.ReadFile(filepath.Join("..", "db", "migrations", "0021_trail_committed_at.sql"))
	if _, err := pool.Exec(string(mig21)); err != nil {
		t.Fatalf("migration 0021: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	// Trail created 2h ago, but the commit is from 6h ago.
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,created_at,git_committed_at)
		VALUES ($1,$2,'t','abc', now() - interval '2 hours', now() - interval '6 hours')`, trail, flow)
	// Deployed 1h ago -> lead time should be 6h-1h = 5h (from commit), not 1h.
	mustExec(t, pool, `INSERT INTO deployment_anchors (org_id,trail_id,ci_sys_id,ci_name,compliant,created_at)
		VALUES ($1,$2,'ci','svc',true, now() - interval '1 hour')`, org, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/dora?days=30", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleDoraMetrics(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dora: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		LeadTimeHours *float64 `json:"lead_time_hours"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.LeadTimeHours == nil || !approx(*out.LeadTimeHours, 5.0, 0.05) {
		t.Fatalf("lead_time_hours = %v, want ~5.0 (from git commit timestamp)", out.LeadTimeHours)
	}
}
