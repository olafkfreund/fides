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

// TestCRAIncidentReport checks the CRA 24h reporting set: exploitable vulns in
// the window are reported with their running environments; VEX-suppressed and
// out-of-window vulns are excluded.
func TestCRAIncidentReport(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the CRA incident report test")
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
	for _, m := range []string{"0012_sbom_components.sql", "0018_vulnerabilities_vex.sql"} {
		mig, _ := os.ReadFile(filepath.Join("..", "db", "migrations", m))
		if _, err := pool.Exec(string(mig)); err != nil {
			t.Fatalf("migration %s: %v", m, err)
		}
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	sha := "cafef00dbaad"
	envID, snapID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc')`, trail, flow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, sha, org, trail)
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, envID, org)
	mustExec(t, pool, `INSERT INTO environment_snapshots (id,environment_id) VALUES ($1,$2)`, snapID, envID)
	mustExec(t, pool, `INSERT INTO snapshot_artifacts (id,snapshot_id,artifact_sha256,service_name,runtime_digest) VALUES ($1,$2,$3,'app','sha256:x')`, uuid.New(), snapID, sha)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	ins := `INSERT INTO artifact_vulnerabilities (id,org_id,artifact_sha256,cve_id,severity,source,created_at) VALUES ($1,$2,$3,$4,$5,'trivy',$6)`
	// Exploitable, in window -> reportable.
	mustExec(t, pool, ins, uuid.New(), org, sha, "CVE-2026-1111", "CRITICAL", nowExpr(t, pool, "- interval '1 hour'"))
	// Suppressed by VEX -> excluded (but counted as suppressed).
	mustExec(t, pool, ins, uuid.New(), org, sha, "CVE-2026-2222", "HIGH", nowExpr(t, pool, "- interval '1 hour'"))
	mustExec(t, pool, `INSERT INTO vex_statements (id,org_id,cve_id,product,status,justification) VALUES ($1,$2,'CVE-2026-2222','','not_affected','n/a')`, uuid.New(), org)
	// Out of the 24h window -> excluded.
	mustExec(t, pool, ins, uuid.New(), org, sha, "CVE-2020-9999", "CRITICAL", nowExpr(t, pool, "- interval '48 hours'"))

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/cra-incidents?hours=24", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleCRAIncidents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cra-incidents: %d %s", rec.Code, rec.Body.String())
	}

	var out struct {
		ReportableCount int `json:"reportable_count"`
		Suppressed      int `json:"vex_suppressed_count"`
		Reportable      []struct {
			CVE          string   `json:"cve"`
			MaxSeverity  string   `json:"max_severity"`
			Artifacts    int      `json:"affected_artifacts"`
			Environments []string `json:"environments"`
		} `json:"reportable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.ReportableCount != 1 || len(out.Reportable) != 1 {
		t.Fatalf("reportable = %+v, want exactly 1 (CVE-2026-1111)", out.Reportable)
	}
	r0 := out.Reportable[0]
	if r0.CVE != "CVE-2026-1111" || r0.MaxSeverity != "CRITICAL" || r0.Artifacts != 1 ||
		len(r0.Environments) != 1 || r0.Environments[0] != "prod" {
		t.Fatalf("reportable[0] = %+v, want CVE-2026-1111/CRITICAL/1 artifact/prod", r0)
	}
	if out.Suppressed != 1 {
		t.Fatalf("vex_suppressed_count = %d, want 1", out.Suppressed)
	}
}

// nowExpr evaluates `now() <expr>` in the DB and returns the timestamp, so tests
// can insert rows at a controlled offset without a bound SQL expression.
func nowExpr(t *testing.T, pool *sql.DB, expr string) interface{} {
	t.Helper()
	var ts interface{}
	if err := pool.QueryRow("SELECT now() " + expr).Scan(&ts); err != nil {
		t.Fatalf("nowExpr(%q): %v", expr, err)
	}
	return ts
}
