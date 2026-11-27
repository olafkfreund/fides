package api

import (
	"archive/zip"
	"bytes"
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
	"fides/pkg/ledger"
	"fides/pkg/models"
)

func TestTrailAuditPackageIntegration(t *testing.T) {
	t.Setenv("FIDES_LEDGER_EVIDENCE_V2", "true")
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the audit-package integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	applyAttestationValidationMigration(t, pool)

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc123')`, trail, flow)
	mustExec(t, pool, `INSERT INTO attestations (trail_id,name,type_name,payload,is_compliant) VALUES ($1,'unit-tests','junit','{"passed":5}',true)`, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	if err := s.appendAttestation(ctx, &models.Attestation{
		ID: uuid.New(), TrailID: trail, Name: "current", TypeName: "junit", Payload: `{"passed":6}`, IsCompliant: true,
	}, nil, attestationEvidence{}); err != nil {
		t.Fatal(err)
	}

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

	chainFile, err := zr.Open("chain-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	defer chainFile.Close()
	var verdict ledger.Verdict
	if err := json.NewDecoder(chainFile).Decode(&verdict); err != nil || !verdict.Valid ||
		verdict.EvidenceCount != 1 || verdict.UnhashedCount != 1 {
		t.Fatalf("audit chain verification = %+v, err = %v", verdict, err)
	}
	attestationFile, err := zr.Open("attestations.json")
	if err != nil {
		t.Fatal(err)
	}
	defer attestationFile.Close()
	var entries []struct {
		Version  int             `json:"hash_version"`
		Evidence json.RawMessage `json:"evidence_inputs"`
	}
	if err := json.NewDecoder(attestationFile).Decode(&entries); err != nil || len(entries) != 2 ||
		entries[1].Version != 2 || len(entries[1].Evidence) == 0 {
		t.Fatalf("audit attestations are missing the v2 proof: %v", err)
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
