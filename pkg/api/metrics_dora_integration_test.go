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

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	// Trail entered the pipeline 3h ago.
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
