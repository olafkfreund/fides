package api

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

func TestTrailAuditPackageIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the audit-package integration test")
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
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc123')`, trail, flow)
	mustExec(t, pool, `INSERT INTO attestations (trail_id,name,type_name,payload,is_compliant) VALUES ($1,'unit-tests','junit','{"passed":5}',true)`, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	req.SetPathValue("id", trail.String())
	rec := httptest.NewRecorder()
	s.handleTrailAuditPackage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("audit package: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content-type = %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	want := map[string]bool{"trail.json": false, "artifacts.json": false, "attestations.json": false, "chain-verification.json": false, "report.md": false}
	for _, f := range zr.File {
		want[f.Name] = true
	}
	for name, present := range want {
		if !present {
			t.Fatalf("audit package missing %s", name)
		}
	}

	// A trail in another org must not be downloadable.
	other := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: uuid.New(), Role: auth.RoleAdmin, Kind: "session"})
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(other)
	req2.SetPathValue("id", trail.String())
	rec2 := httptest.NewRecorder()
	s.handleTrailAuditPackage(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant access should be 404, got %d", rec2.Code)
	}
}
