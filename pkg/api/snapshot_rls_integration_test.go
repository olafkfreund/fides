package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fides/pkg/auth"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// TestReportSnapshotSatisfiesTenantRLSIntegration is the regression test for
// https://github.com/olafkfreund/fides/issues/246.
//
// POST /api/v1/snapshots (handleReportSnapshot) used to begin its insert
// transaction on the raw, unscoped connection pool, which never had the
// tenant GUC (app.current_org) set. Under FIDES_RLS_ENABLED, the
// environment_snapshots RLS policy's WITH CHECK subquery
// (`environment_id IN (SELECT id FROM environments)`) is itself evaluated
// under RLS with no org context, returns an empty set, and the insert is
// rejected with `pq: new row violates row-level security policy for table
// "environment_snapshots" (42501)` -> the handler returned 500 for every
// request.
//
// This test spins up a real, non-superuser-scoped Postgres role (RLS is not
// enforced for the table owner/superuser), applies schema.sql +
// schema-rls.sql exactly as production does, and drives the handler over
// real HTTP. It also proves the secondary finding from the issue: once the
// snapshot write succeeds under the correct tenant context, the environment
// list's LastSnapshot derivation (a simple MAX(created_at) query scoped by
// the same RLS-pinned connection) immediately reflects it — i.e. the read
// side was never separately broken, it just never received a successfully
// committed row to find.
func TestReportSnapshotSatisfiesTenantRLSIntegration(t *testing.T) {
	superDSN := os.Getenv("FIDES_TEST_DB_DSN")
	if superDSN == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the snapshot RLS integration test")
	}

	readRepo := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}

	// --- Setup as superuser: schema, RLS, least-privilege app role, seed data.
	super, err := sql.Open("postgres", superDSN)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	defer super.Close()
	if err := super.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	mustExec := func(q string, args ...any) {
		if _, err := super.Exec(q, args...); err != nil {
			t.Fatalf("exec failed: %v\nSQL: %.100s", err, q)
		}
	}
	mustExec(readRepo("schema.sql"))
	mustExec(readRepo("schema-rls.sql"))
	mustExec(`DO $$ BEGIN
	            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_snap_app') THEN
	              CREATE ROLE fides_snap_app LOGIN PASSWORD 'app';
	            END IF;
	          END $$;
	          GRANT USAGE ON SCHEMA public TO fides_snap_app;
	          GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_snap_app;
	          GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_snap_app;`)

	orgID := uuid.New()
	envID := uuid.New()
	mustExec(`INSERT INTO organizations (id, name) VALUES ($1,$2)`, orgID, "org-"+orgID.String()[:8])
	mustExec(`INSERT INTO environments (id, org_id, name, type, description) VALUES ($1,$2,'prod-k8s','k8s','')`, envID, orgID)
	t.Cleanup(func() { _, _ = super.Exec(`DELETE FROM organizations WHERE id = $1`, orgID) })

	// --- The server's pool connects as the non-superuser app role so RLS applies.
	appDSN := withUserPassword(superDSN, "fides_snap_app", "app")
	appPool, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()
	if err := appPool.Ping(); err != nil {
		t.Fatalf("app ping: %v", err)
	}

	t.Setenv("FIDES_RLS_ENABLED", "true")
	t.Setenv("FIDES_API_TOKEN", "unused-but-required")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	srv := NewServer(appPool, nil, nil)
	token, err := srv.Sessions.Create(auth.Principal{OrgID: orgID, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	postSnapshot := func() *http.Response {
		body, _ := json.Marshal(map[string]any{
			"environment_id": envID.String(),
			"artifacts":      []any{},
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/snapshots", bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return resp
	}

	// This is the exact repro from the issue: POST with an empty artifacts
	// array against a real, RLS-enabled environment_snapshots table. Before
	// the fix, this returns 500 with a 42501 RLS violation logged server-side.
	resp := postSnapshot()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 from POST /api/v1/snapshots, got %d", resp.StatusCode)
	}
	var reported snapshotReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&reported); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if reported.SnapshotID == uuid.Nil {
		t.Fatalf("expected a non-nil snapshot_id in the response")
	}

	// Confirm the row actually landed (as superuser, bypassing RLS for the check).
	var count int
	if err := super.QueryRow(`SELECT COUNT(*) FROM environment_snapshots WHERE id = $1 AND environment_id = $2`,
		reported.SnapshotID, envID).Scan(&count); err != nil {
		t.Fatalf("verify snapshot row: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 environment_snapshots row for id=%s, got %d", reported.SnapshotID, count)
	}

	// Secondary finding from the issue: does GET /api/v1/environments now
	// surface the snapshot (LastSnapshot / "last_reported_at")? It should,
	// since it derives from the same environment_snapshots row via the same
	// RLS-scoped connection.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/environments", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	getResp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET environments: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/v1/environments, got %d", getResp.StatusCode)
	}
	var envs []struct {
		ID           string `json:"id"`
		LastSnapshot string `json:"lastSnapshot"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&envs); err != nil {
		t.Fatalf("decode environments: %v", err)
	}
	var found bool
	for _, e := range envs {
		if e.ID == envID.String() {
			found = true
			if e.LastSnapshot == "No snapshot reported yet" || e.LastSnapshot == "" {
				t.Fatalf("expected environment %s to show a reported snapshot time, got %q", envID, e.LastSnapshot)
			}
		}
	}
	if !found {
		t.Fatalf("environment %s not present in GET /api/v1/environments response", envID)
	}
}
