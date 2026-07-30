package api

import (
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
	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/policy"
)

// Regression for #326: attestation_types is org-scoped (UNIQUE(org_id,name)), so
// the JQ-rule lookup in handleReportAttestation must be scoped by org_id. Here
// ONLY org B defines a type "leak-check" whose rule the payload fails. Reporting
// under org A (which has no such type) must resolve to zero rules and come back
// compliant — an unscoped lookup would apply org B's rule and mark it
// non-compliant, leaking one tenant's policy onto another's evidence.
func TestAttestationJQRulesScopedByOrg(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the attestation org-scope integration test")
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

	orgA, orgB := uuid.New(), uuid.New()
	flowA, trailA := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgA, "a-"+orgA.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgB, "b-"+orgB.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flowA, orgA)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trailA, flowA)
	// Only org B registers the type, with a rule the reported payload fails.
	mustExec(t, pool, `INSERT INTO attestation_types (id,org_id,name,description,schema,jq_rules,created_at)
		VALUES ($1,$2,'leak-check','','{}',$3,now())`,
		uuid.New(), orgB, pq.Array([]string{`.approved == true`}))
	t.Cleanup(func() {
		pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB)
	})

	s := &Server{DB: pool, PolicyEngine: policy.NewPolicyEngine()}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: orgA, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(reportAttestationReq{
		TrailID:  trailA.String(),
		Name:     "x",
		TypeName: "leak-check",
		Payload:  `{"approved": false}`, // fails org B's `.approved == true` rule
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestations", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleReportAttestation(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record attestation: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode attestation: %v", err)
	}

	var compliant bool
	if err := pool.QueryRow(`SELECT is_compliant FROM attestations WHERE id=$1`, created.ID).Scan(&compliant); err != nil {
		t.Fatalf("read is_compliant: %v", err)
	}
	if !compliant {
		t.Fatalf("cross-tenant policy bleed (#326): org B's JQ rule was applied to org A's attestation")
	}
}
