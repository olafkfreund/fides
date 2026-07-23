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

// TestBackfillVulnerabilities checks that CVEs are extracted from a pre-existing
// scan attestation (one recorded before CVE extraction shipped) and that the
// backfill is idempotent.
func TestBackfillVulnerabilities(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the vulnerability backfill test")
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
	mig, _ := os.ReadFile(filepath.Join("..", "db", "migrations", "0018_vulnerabilities_vex.sql"))
	if _, err := pool.Exec(string(mig)); err != nil {
		t.Fatalf("migration 0018: %v", err)
	}

	org, flow, trail, attID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sha := "beefbeefbeef"
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc')`, trail, flow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, sha, org, trail)
	// A trivy scan attestation recorded directly (as if before CVE extraction) —
	// no artifact_vulnerabilities rows exist for it yet.
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,artifact_sha256,name,type_name,payload,is_compliant)
		VALUES ($1,$2,$3,'scan','trivy',$4,false)`, attID, trail, sha,
		`{"findings":["CRITICAL: CVE-2021-44228","HIGH: CVE-2020-0001"]}`)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	run := func() struct {
		Scanned int `json:"attestations_scanned"`
		Added   int `json:"vulnerabilities_added"`
		Total   int `json:"vulnerabilities_total"`
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/backfill", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleBackfillVulnerabilities(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("backfill: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Scanned int `json:"attestations_scanned"`
			Added   int `json:"vulnerabilities_added"`
			Total   int `json:"vulnerabilities_total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	first := run()
	if first.Scanned != 1 || first.Added != 2 || first.Total != 2 {
		t.Fatalf("first backfill = %+v, want scanned=1 added=2 total=2", first)
	}
	// The CVEs are now queryable.
	var n int
	pool.QueryRow(`SELECT count(*) FROM artifact_vulnerabilities WHERE org_id=$1 AND artifact_sha256=$2`, org, sha).Scan(&n)
	if n != 2 {
		t.Fatalf("artifact_vulnerabilities rows = %d, want 2", n)
	}

	// Idempotent: a second run adds nothing.
	second := run()
	if second.Added != 0 || second.Total != 2 {
		t.Fatalf("second backfill = %+v, want added=0 total=2 (idempotent)", second)
	}
}
