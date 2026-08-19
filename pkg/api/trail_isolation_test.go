package api

import (
	"context"
	"database/sql"
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

func trailProbeDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN")
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
	return pool
}

// twoTenantTrails returns (myOrg, theirTrailID). Their trail carries an
// attestation whose payload holds a secret.
func twoTenantTrails(t *testing.T, pool *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	mine, theirs := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, theirs, "theirs-"+theirs.String()[:8])
	theirFlow, theirTrail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'their-svc')`, theirFlow, theirs)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'their-build')`, theirTrail, theirFlow)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,content_hash)
	                   VALUES ($1,$2,'unit-tests','test','{"secret":"THEIR-PAYLOAD-SECRET"}'::jsonb,true,'abc')`,
		uuid.New(), theirTrail)
	t.Cleanup(func() {
		pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, mine, theirs)
	})
	return mine, theirTrail
}

func principalCtx(org uuid.UUID) context.Context {
	return auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "service"})
}

// The chain-verify endpoint reads every attestation payload on the trail.
func TestVerifyTrailChainDoesNotLeakAnotherTenantsPayloads(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trails/"+theirTrail.String()+"/verify-chain", nil)
	req.SetPathValue("id", theirTrail.String())
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleVerifyTrailChain(rec, req)

	body := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, body)
	// The endpoint returns a verdict, not the payloads, so asserting on payload
	// text would pass even while it reads the chain. `count` is the tell: it is
	// the number of another tenant's attestations this call walked.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's trail, got %d: %s", rec.Code, body)
	}
	if strings.Contains(body, `"count":1`) {
		t.Fatalf("LEAK: walked another tenant's attestation chain: %s", body)
	}
}

// The change gate returns a compliance verdict over the trail's attestations.
func TestChangeGateDoesNotEvaluateAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trails/"+theirTrail.String()+"/change-gate", nil)
	req.SetPathValue("id", theirTrail.String())
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleChangeGate(rec, req)

	body := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, body)
	// Same trap: the verdict does not name the attestation types, so the tell is
	// the count of attestations the gate found on their trail.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's trail, got %d: %s", rec.Code, body)
	}
	if strings.Contains(body, `"total":1`) {
		t.Fatalf("LEAK: evaluated another tenant's trail: %s", body)
	}
	// The gate also emits a segregation-of-duties attestation (sod.go), so an
	// unguarded GET does not merely read — it writes evidence into another
	// tenant's chain.
	var n int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name <> 'test'`, theirTrail).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: a GET wrote %d attestation(s) into another tenant's chain", n)
	}
}

// Writing an attestation onto another tenant's trail is evidence forgery.
func TestVerifyBranchProtectionCannotWriteToAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)

	srv := NewServer(pool, nil, nil)
	body := `{"trail_id":"` + theirTrail.String() + `","repo":"acme/app","branch":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/branch-protection/verify", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleVerifyBranchProtection(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	// Without a guard this returns 400 "no matching git provider" — a
	// configuration accident, not a refusal. With a provider configured for the
	// repo it would go on to write. The ownership check must come first, so the
	// contract asserted here is the status, not just the absence of a row.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's trail, got %d: %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name <> 'test'`, theirTrail).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: wrote %d attestation(s) onto another tenant's trail (status %d)", n, rec.Code)
	}
}

// The headline case: the change gate emits a segregation-of-duties attestation,
// so an unguarded GET appends evidence to another tenant's append-only ledger.
// Needs COMPLETE SoD evidence on the target trail — without it the emitter takes
// its "evidence incomplete" early return and the write never happens, which is
// why a naive probe of this shows nothing.
func TestChangeGateDoesNotWriteSoDEvidenceOntoAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)
	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT f.org_id FROM trails t JOIN flows f ON f.id=t.flow_id WHERE t.id=$1`,
		theirTrail).Scan(&theirOrg); err != nil {
		t.Fatalf("org: %v", err)
	}
	mustExec(t, pool, `UPDATE trails SET tags = '{"committer":"dev@theirs.example"}'::jsonb WHERE id=$1`, theirTrail)
	mustExec(t, pool, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind,role)
	                   VALUES ($1,$2,'lead@theirs.example','session','approver')`, theirOrg, theirTrail)
	mustExec(t, pool, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind,role)
	                   VALUES ($1,$2,'ci@theirs.example','service','deployer')`, theirOrg, theirTrail)

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trails/"+theirTrail.String()+"/change-gate", nil)
	req.SetPathValue("id", theirTrail.String())
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleChangeGate(rec, req)

	var n int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name='segregation-of-duties'`,
		theirTrail).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	t.Logf("status=%d sod_attestations=%d", rec.Code, n)
	if n != 0 {
		t.Fatalf("LEAK: a GET appended %d SoD attestation(s) to another tenant's ledger", n)
	}
}

func TestAttestFetchRefusesAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)

	srv := NewServer(pool, nil, nil)
	body := `{"trail_id":"` + theirTrail.String() + `","artifact_sha256":"` + strings.Repeat("ab", 32) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest/fetch", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleAttestFetch(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's trail, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServiceNowChangeGateRefusesAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)

	srv := NewServer(pool, nil, nil)
	body := `{"trail_id":"` + theirTrail.String() + `","change_number":"CHG0012345"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/servicenow/change-gate", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleServiceNowChangeGate(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's trail, got %d: %s", rec.Code, rec.Body.String())
	}
}

// The legitimate path: CI pipelines call the gate and the chain verifier on
// every build, so a guard that is too strict breaks everything.
func TestTrailEndpointsStillWorkWithinYourOwnOrg(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	flow, trail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'my-svc')`, flow, mine)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'my-build')`, trail, flow)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,content_hash)
	                   VALUES ($1,$2,'unit-tests','test','{}'::jsonb,true,'abc')`, uuid.New(), trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"change-gate", srv.handleChangeGate},
		{"verify-chain", srv.handleVerifyTrailChain},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.SetPathValue("id", trail.String())
		req = req.WithContext(principalCtx(mine))
		rec := httptest.NewRecorder()
		tc.fn(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s on own trail should be 200, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
	}
}
