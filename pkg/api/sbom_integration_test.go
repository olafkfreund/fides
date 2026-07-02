package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/evidence"
)

// End-to-end: `fides attest sbom` normalizes a CycloneDX SBOM client-side (see
// pkg/evidence.ParseSBOM) and POSTs it to /api/v1/attestations; the server
// persists a component row per package (linked to the artifact) and resolves
// trail_id from the artifact when it is omitted. Gated by FIDES_TEST_DB_DSN.
func TestSBOMIngestionIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the SBOM ingestion integration test")
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
	// sbom_components is not yet baked into schema.sql (it ships as an
	// additive migration for existing databases); apply it explicitly here.
	migration, err := os.ReadFile(filepath.Join("..", "..", "pkg", "db", "migrations", "0012_sbom_components.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := pool.Exec(string(migration)); err != nil {
		t.Fatalf("apply sbom_components migration: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	sum := sha256.Sum256([]byte("sbom-integration-" + org.String()))
	artifactSHA := hex.EncodeToString(sum[:])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, artifactSHA, org, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	cdxDoc := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
			{"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"}
		]
	}`)
	result, err := evidence.ParseSBOM(cdxDoc)
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// Record the attestation WITHOUT a trail_id: the server must resolve it
	// from the artifact.
	reqBody, _ := json.Marshal(reportAttestationReq{
		ArtifactSHA256: artifactSHA,
		Name:           "sbom",
		TypeName:       "sbom-cyclonedx",
		Payload:        string(payload),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestations", bytes.NewReader(reqBody)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleReportAttestation(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record sbom attestation: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID      uuid.UUID `json:"id"`
		TrailID uuid.UUID `json:"trail_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	if created.TrailID != trail {
		t.Fatalf("expected trail_id resolved from artifact %s, got %s", trail, created.TrailID)
	}

	// Components must be persisted, linked to the artifact.
	var count int
	if err := pool.QueryRow(`SELECT count(*) FROM sbom_components WHERE artifact_sha256=$1`, artifactSHA).Scan(&count); err != nil {
		t.Fatalf("count components: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 persisted components, got %d", count)
	}

	// `fides search components --purl <p>` must find the artifact.
	sreq := httptest.NewRequest(http.MethodGet, "/api/v1/search/components?purl=pkg:npm/lodash@4.17.21", nil).WithContext(ctx)
	srec := httptest.NewRecorder()
	s.handleSearchComponents(srec, sreq)
	if srec.Code != http.StatusOK {
		t.Fatalf("search components: HTTP %d: %s", srec.Code, srec.Body.String())
	}
	var results []map[string]any
	if err := json.Unmarshal(srec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode search results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 match for the lodash purl, got %d: %+v", len(results), results)
	}
	if results[0]["artifact_sha256"] != artifactSHA {
		t.Fatalf("expected artifact %s in results, got %+v", artifactSHA, results[0])
	}

	// Neither --trail nor a resolvable artifact must be rejected.
	badBody, _ := json.Marshal(reportAttestationReq{Name: "sbom", TypeName: "sbom-cyclonedx", Payload: `{}`})
	breq := httptest.NewRequest(http.MethodPost, "/api/v1/attestations", bytes.NewReader(badBody)).WithContext(ctx)
	breq.Header.Set("Content-Type", "application/json")
	brec := httptest.NewRecorder()
	s.handleReportAttestation(brec, breq)
	if brec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when trail_id and artifact_sha256 are both absent, got %d", brec.Code)
	}
}
