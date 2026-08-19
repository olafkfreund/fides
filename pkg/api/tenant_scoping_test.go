package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// The two handlers a sweep of pkg/api found still reaching the database with no
// tenant scoping of any kind, after #457 and #458 fixed the environment and
// trail families.
//
// authMiddleware states the contract: "The Principal's OrgID is the ONLY source
// of tenant scoping downstream". RLS is a second layer rather than the first —
// it is opt-in via FIDES_RLS_ENABLED and s.q() falls back to the unscoped pool
// when it is off, so a handler that does not scope itself has no isolation at
// all in a default deployment.
//
// Both began as probes that failed against the unfixed handlers.

// asWriter builds a request authenticated as a Writer in the given org.
func asWriter(org uuid.UUID, method, target, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	return r.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: org, Role: auth.RoleWriter, Kind: "service"}))
}

// Renaming another tenant's pipeline is a cross-tenant write, and it needs only
// the flow's uuid — which is not a secret, being returned by the API and
// appearing in URLs. handleListFlows immediately below it scopes correctly, so
// this was an inconsistency rather than a design.
func TestUpdateFlowCannotTouchAnotherTenant(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)
	_ = theirEnv

	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT org_id FROM environments WHERE id=$1`, theirEnv).Scan(&theirOrg); err != nil {
		t.Fatalf("locating the other tenant: %v", err)
	}
	victim := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'their-pipeline','')`, victim, theirOrg)

	srv := NewServer(pool, nil, nil)
	rec := httptest.NewRecorder()
	srv.handleUpdateFlow(rec, asWriter(mine, http.MethodPut, "/api/v1/flows",
		`{"id":"`+victim.String()+`","name":"owned","description":"owned"}`))

	var name string
	if err := pool.QueryRow(`SELECT name FROM flows WHERE id=$1`, victim).Scan(&name); err != nil {
		t.Fatalf("reading the victim flow: %v", err)
	}
	if name != "their-pipeline" {
		t.Errorf("a tenant renamed another tenant's flow to %q (status %d)", name, rec.Code)
	}
	// Not merely "nothing happened": a silent 200 reports success for a write
	// that did not occur. 404 rather than 403 on purpose, so the response
	// cannot be used to test whether a flow id exists in another organization.
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 — a no-op reported as success is a lie to the caller", rec.Code)
	}
}

// A flow in your own org must still be updatable, or the fix above is just a
// broken endpoint.
func TestUpdateFlowStillWorksWithinYourOwnOrg(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, _ := twoTenants(t, pool)

	own := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'before','')`, own, mine)

	srv := NewServer(pool, nil, nil)
	rec := httptest.NewRecorder()
	srv.handleUpdateFlow(rec, asWriter(mine, http.MethodPut, "/api/v1/flows",
		`{"id":"`+own.String()+`","name":"after","description":"d"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("updating your own flow: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var name string
	if err := pool.QueryRow(`SELECT name FROM flows WHERE id=$1`, own).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "after" {
		t.Errorf("name = %q, want after", name)
	}
}

// The compliance verdict for a digest says whether somebody else's artifact
// passed its controls, and names it. An image digest is not a secret — it is in
// every manifest and registry listing — so before this was scoped, the
// compliance posture of any organisation's builds was answerable by anyone with
// an account who knew what they shipped.
func TestCheckComplianceIsScopedToTheCallersOrg(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)

	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT org_id FROM environments WHERE id=$1`, theirEnv).Scan(&theirOrg); err != nil {
		t.Fatalf("locating the other tenant: %v", err)
	}
	flow, trail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, theirOrg)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc')`, trail, flow)
	digest := strings.Repeat("a", 64)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'their-secret-service','docker')`,
		digest, theirOrg, trail)

	srv := NewServer(pool, nil, nil)
	rec := httptest.NewRecorder()
	srv.handleCheckCompliance(rec, asWriter(mine, http.MethodGet, "/api/v1/compliance/check?sha256="+digest, ""))

	if strings.Contains(rec.Body.String(), "their-secret-service") {
		t.Errorf("a tenant learned about another tenant's artifact: %s", rec.Body.String())
	}
}

// And an artifact in your own org is still found, so the scoping did not turn
// the endpoint into one that always answers "unknown".
func TestCheckComplianceStillFindsYourOwnArtifact(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, _ := twoTenants(t, pool)

	flow, trail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, mine)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc')`, trail, flow)
	digest := strings.Repeat("b", 64)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'my-service','docker')`,
		digest, mine, trail)

	srv := NewServer(pool, nil, nil)
	rec := httptest.NewRecorder()
	srv.handleCheckCompliance(rec, asWriter(mine, http.MethodGet, "/api/v1/compliance/check?sha256="+digest, ""))

	if !strings.Contains(rec.Body.String(), "my-service") {
		t.Errorf("your own artifact was not found: code=%d body=%s", rec.Code, rec.Body.String())
	}
}
