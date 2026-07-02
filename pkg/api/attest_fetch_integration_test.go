package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/vault"
)

// randSHA256 derives a syntactically valid, run-unique sha256 hex digest, so
// tests don't collide on artifacts.sha256 (a global primary key) if a
// previous run's cleanup didn't get to run (e.g. the process was killed).
func randSHA256() string {
	sum := sha256.Sum256([]byte(uuid.New().String()))
	return fmt.Sprintf("%x", sum)
}

// End-to-end: handleAttestFetch resolves the tenant's configured GitHub
// provider, fetches a (faked) Artifact Attestations bundle, normalizes it,
// and records it as a "provenance" attestation on the trail's tamper-evidence
// chain. Gated by FIDES_TEST_DB_DSN.
func TestAttestFetchIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the attest-fetch integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Registered before any other t.Cleanup so it runs last (LIFO): other
	// cleanups need a live pool.
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	sha := randSHA256()
	statement := []byte(`{"predicateType":"https://slsa.dev/provenance/v1",` +
		`"subject":[{"name":"app","digest":{"sha256":"` + sha + `"}}],` +
		`"predicate":{"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}}}`)
	bundle, _ := json.Marshal(map[string]any{
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(statement),
			"payloadType": "application/vnd.in-toto+json",
		},
	})

	mux := http.NewServeMux()
	gh := httptest.NewServer(mux)
	defer gh.Close()
	mux.HandleFunc("/repos/acme/widgets/attestations/sha256:"+sha, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"attestations":[{"bundle_url":"%s/repos/acme/widgets/attestations/sha256:%s/bundle"}]}`, gh.URL, sha)
	})
	mux.HandleFunc("/repos/acme/widgets/attestations/sha256:"+sha+"/bundle", func(w http.ResponseWriter, r *http.Request) {
		w.Write(bundle)
	})

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	// Register cleanup immediately after the org exists (and before any
	// artifacts.sha256 insert, since that's a global PK) so a failure partway
	// through setup can't leave rows behind that collide with a later run.
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool,
		`INSERT INTO trails (id,flow_id,name,git_repository,git_commit) VALUES ($1,$2,'t','https://github.com/acme/widgets','deadbeef')`,
		trail, flow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, sha, org, trail)
	t.Setenv("TEST_ATTEST_FETCH_TOKEN", "tok123")
	mustExec(t, pool,
		`INSERT INTO tenant_git_providers (org_id,provider,host,api_base,token_path,enabled) VALUES ($1,'github','github.com',$2,'TEST_ATTEST_FETCH_TOKEN',true)`,
		org, gh.URL)

	s := &Server{DB: pool, Secrets: vault.NewEnvSecretsProvider(), httpClient: gh.Client()}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(map[string]any{"trail_id": trail.String(), "artifact_sha256": sha})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest/fetch", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleAttestFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["recorded"] != float64(1) || resp["compliant"] != true || resp["provider"] != "github" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	var count int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name='provenance' AND artifact_sha256=$2 AND is_compliant=true`,
		trail, sha).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 compliant provenance attestation, got %d", count)
	}
}

// A request naming an unconfigured provider is rejected with 400, without
// touching any external API.
func TestAttestFetchIntegrationNoProviderConfigured(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the attest-fetch integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	sha := randSHA256()
	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool,
		`INSERT INTO trails (id,flow_id,name,git_repository,git_commit) VALUES ($1,$2,'t','https://github.com/acme/widgets','deadbeef')`,
		trail, flow)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool, Secrets: vault.NewEnvSecretsProvider(), httpClient: http.DefaultClient}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(map[string]any{"trail_id": trail.String(), "artifact_sha256": sha})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest/fetch", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleAttestFetch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no configured provider, got %d: %s", rec.Code, rec.Body.String())
	}
}
