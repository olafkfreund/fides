package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// handlePolicyCheck names an environment in the path. Every other handler in
// policies.go verifies it belongs to the caller; this one did not, and the
// response prints each policy's name and its required attestation types — which
// is another tenant's compliance regime.
func TestPolicyCheckDoesNotLeakAnotherTenantsPolicies(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)
	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT f.org_id FROM trails t JOIN flows f ON f.id=t.flow_id WHERE t.id=$1`,
		theirTrail).Scan(&theirOrg); err != nil {
		t.Fatalf("org: %v", err)
	}
	theirEnv := uuid.New()
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'their-prod','k8s')`,
		theirEnv, theirOrg)
	mustExec(t, pool, `INSERT INTO environment_policies (id,environment_id,name,required_types,enabled)
	                   VALUES ($1,$2,'pci-dss-cardholder-data',$3,true)`,
		uuid.New(), theirEnv, pq.Array([]string{"their-secret-scan", "their-pentest"}))

	// Our own trail, so the trail check passes and only the environment is foreign.
	myFlow, myTrail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'mine')`, myFlow, mine)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'b')`, myTrail, myFlow)

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/x?trail="+myTrail.String(), nil)
	req.SetPathValue("id", theirEnv.String())
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handlePolicyCheck(rec, req)

	body := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, body)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's environment, got %d: %s", rec.Code, body)
	}
	if strings.Contains(body, "pci-dss-cardholder-data") || strings.Contains(body, "their-secret-scan") {
		t.Fatalf("LEAK: another tenant's policy configuration was returned: %s", body)
	}
}

func TestPolicyCheckStillWorksInYourOwnEnvironment(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	env, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, env, mine)
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'mine')`, flow, mine)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'b')`, trail, flow)
	mustExec(t, pool, `INSERT INTO environment_policies (id,environment_id,name,required_types,enabled)
	                   VALUES ($1,$2,'my-policy',$3,true)`, uuid.New(), env, pq.Array([]string{"test"}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/x?trail="+trail.String(), nil)
	req.SetPathValue("id", env.String())
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handlePolicyCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("own-env policy check should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "my-policy") {
		t.Fatalf("own policy should still be evaluated, got %s", rec.Body.String())
	}
}
