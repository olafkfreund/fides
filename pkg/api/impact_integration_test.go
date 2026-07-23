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

// TestCVEImpactIndexWithVEX exercises the full slice: extract CVEs from a
// vuln-scan payload -> query which environments run the affected artifact ->
// suppress with a VEX not_affected statement.
func TestCVEImpactIndexWithVEX(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the CVE impact integration test")
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
	migration, _ := os.ReadFile(filepath.Join("..", "db", "migrations", "0018_vulnerabilities_vex.sql"))
	if _, err := pool.Exec(string(migration)); err != nil {
		t.Fatalf("migration 0018: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	sha := "a1b2c3d4e5f6"
	envID, snapID, attID := uuid.New(), uuid.New(), uuid.New()
	cve := "CVE-2021-44228"

	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc')`, trail, flow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, sha, org, trail)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,artifact_sha256,name,type_name,payload) VALUES ($1,$2,$3,'scan','trivy','{}')`, attID, trail, sha)
	// Artifact is running in a prod environment.
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, envID, org)
	mustExec(t, pool, `INSERT INTO environment_snapshots (id,environment_id) VALUES ($1,$2)`, snapID, envID)
	mustExec(t, pool, `INSERT INTO snapshot_artifacts (id,snapshot_id,artifact_sha256,service_name,runtime_digest) VALUES ($1,$2,$3,'app','sha256:xyz')`, uuid.New(), snapID, sha)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	// A DIFFERENT tenant runs the SAME (globally-keyed) artifact sha in its own
	// environment. Org A's impact query must never surface Org B's environment.
	orgB, envB, snapB := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgB, "b-"+orgB.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'other-tenant-prod','k8s')`, envB, orgB)
	mustExec(t, pool, `INSERT INTO environment_snapshots (id,environment_id) VALUES ($1,$2)`, snapB, envB)
	mustExec(t, pool, `INSERT INTO snapshot_artifacts (id,snapshot_id,artifact_sha256,service_name,runtime_digest) VALUES ($1,$2,$3,'app','sha256:xyz')`, uuid.New(), snapB, sha)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, orgB) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	// Extract CVEs from a trivy-style findings payload.
	payload := `{"findings":["CRITICAL: ` + cve + `","HIGH: CVE-2020-0001"]}`
	if err := s.persistVulnerabilities(ctx, org, sha, attID, "trivy", payload); err != nil {
		t.Fatalf("persistVulnerabilities: %v", err)
	}

	// Impact query: artifact affected, running in prod, nothing suppressed.
	got := impact(t, s, ctx, cve)
	if got.AffectedCount != 1 || got.DeployedCount != 1 || got.Suppressed != 0 {
		t.Fatalf("pre-VEX impact = %+v, want affected=1 deployed=1 suppressed=0", got)
	}
	if len(got.Artifacts) != 1 || len(got.Artifacts[0].Environments) != 1 ||
		got.Artifacts[0].Environments[0].Environment != "prod" || got.Artifacts[0].Severity != "CRITICAL" {
		t.Fatalf("impact artifacts = %+v, want prod/CRITICAL", got.Artifacts)
	}

	// Record an org-wide not_affected VEX statement for the CVE.
	body := `{"cve":"` + cve + `","status":"not_affected","justification":"not reachable"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex", strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleRecordVEX(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record vex: %d %s", rec.Code, rec.Body.String())
	}

	// Now the CVE is suppressed: no affected artifacts, one suppressed.
	got = impact(t, s, ctx, cve)
	if got.AffectedCount != 0 || got.Suppressed != 1 {
		t.Fatalf("post-VEX impact = %+v, want affected=0 suppressed=1", got)
	}
}

type impactResp struct {
	AffectedCount int `json:"affected_artifact_count"`
	DeployedCount int `json:"deployed_artifact_count"`
	Suppressed    int `json:"vex_suppressed_count"`
	Artifacts     []struct {
		Severity     string `json:"severity"`
		Environments []struct {
			Environment string `json:"environment"`
		} `json:"environments"`
	} `json:"affected_artifacts"`
}

func impact(t *testing.T, s *Server, ctx context.Context, cve string) impactResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/impact?cve="+cve, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleImpact(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("impact: %d %s", rec.Code, rec.Body.String())
	}
	var out impactResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	return out
}
