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

// invokeSaveUser drives handleSaveUser (POST /api/v1/tenant/users) — the
// identity-registration endpoint (#279) — with a principal on the context.
func invokeSaveUser(t *testing.T, s *Server, p *auth.Principal, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenant/users", strings.NewReader(string(buf)))
	req = req.WithContext(auth.WithPrincipal(context.Background(), p))
	rec := httptest.NewRecorder()
	s.handleSaveUser(rec, req)
	return rec
}

// invokeChangeGate drives handleChangeGate (GET /api/v1/trails/{id}/change-gate)
// and returns the decoded verdict, including the segregation_of_duties sub-object.
func invokeChangeGate(t *testing.T, s *Server, p *auth.Principal, trailID uuid.UUID) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trails/"+trailID.String()+"/change-gate", nil)
	req.SetPathValue("id", trailID.String())
	req = req.WithContext(auth.WithPrincipal(context.Background(), p))
	rec := httptest.NewRecorder()
	s.handleChangeGate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-gate code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode change-gate: %v", err)
	}
	return out
}

// TestSegregationOfDutiesReachableGreenIntegration is the epic #280 acceptance
// test: a trail with three DISTINCT registered identities — committer X (trail
// tag, #277), approver Y and deployer Z (registered via the /tenant/users API,
// #279, and recorded with role=approver / role=deployer, #278) — yields a
// segregation-of-duties payload with compliant:true and no violations, each
// identity supplied through a documented API.
func TestSegregationOfDutiesReachableGreenIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the SoD reachable-green integration test")
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

	const (
		committer = "dev@example.com"        // #277: supplied as a trail tag
		approver  = "approver@example.com"   // #278 role=approver / #279 registered
		deployer  = "ci-deployer@example.com" // #278 role=deployer  / #279 registered
	)

	org := uuid.New()
	flow := uuid.New()
	trail := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	// #277: the committer is a property of the commit, supplied as the trail tag
	// `committer` (what `fides trail start --committer` persists).
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,tags) VALUES ($1,$2,'t','abc123',$3::jsonb)`,
		trail, flow, `{"committer":"`+committer+`"}`)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	admin := &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "service"}
	t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")

	// #279: register the approver and deployer identities via the documented
	// registration endpoint. Without this, on_behalf_of rejects them (400).
	for _, u := range []string{approver, deployer} {
		if rec := invokeSaveUser(t, s, admin, map[string]any{"name": u, "email": u, "role": "Writer"}); rec.Code != http.StatusOK {
			t.Fatalf("register %s: code=%d body=%s", u, rec.Code, rec.Body.String())
		}
	}

	// #278: record the approver (role=approver) and the deployer (role=deployer),
	// each attributed to its registered identity via on_behalf_of.
	if rec := invokeRecordApproval(t, s, admin, trail, map[string]any{"role": "approver", "on_behalf_of": approver}); rec.Code != http.StatusCreated {
		t.Fatalf("approver approval: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := invokeRecordApproval(t, s, admin, trail, map[string]any{"role": "deployer", "on_behalf_of": deployer}); rec.Code != http.StatusCreated {
		t.Fatalf("deployer approval: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// The change-gate SoD payload must now be compliant with no violations.
	gate := invokeChangeGate(t, s, admin, trail)
	sodRaw, ok := gate["segregation_of_duties"]
	if !ok {
		t.Fatalf("change-gate missing segregation_of_duties: %v", gate)
	}
	sodBytes, _ := json.Marshal(sodRaw)
	var sod sodAttestation
	if err := json.Unmarshal(sodBytes, &sod); err != nil {
		t.Fatalf("decode sod: %v", err)
	}

	if !sod.Compliant {
		t.Fatalf("SoD not compliant: %+v", sod)
	}
	if len(sod.Violations) != 0 {
		t.Fatalf("expected no violations, got %v", sod.Violations)
	}
	if sod.Committer != committer {
		t.Fatalf("committer = %q, want %q", sod.Committer, committer)
	}
	if len(sod.Approvers) != 1 || sod.Approvers[0] != approver {
		t.Fatalf("approvers = %v, want [%s]", sod.Approvers, approver)
	}
	if len(sod.Deployers) != 1 || sod.Deployers[0] != deployer {
		t.Fatalf("deployers = %v, want [%s]", sod.Deployers, deployer)
	}

	// #278 (gate output): the deployer must appear under approvals.deployers, not
	// approvals.approvers.
	approvals, _ := gate["approvals"].(map[string]any)
	if approvals == nil {
		t.Fatalf("change-gate missing approvals: %v", gate)
	}
	gateApprovers := toStringSlice(approvals["approvers"])
	gateDeployers := toStringSlice(approvals["deployers"])
	if !contains(gateDeployers, deployer) {
		t.Fatalf("gate approvals.deployers = %v, want it to contain %s", gateDeployers, deployer)
	}
	if contains(gateApprovers, deployer) {
		t.Fatalf("deployer %s must not appear in gate approvals.approvers %v", deployer, gateApprovers)
	}
}

func toStringSlice(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
