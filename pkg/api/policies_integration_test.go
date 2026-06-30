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
	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

func TestEnvironmentPolicyCheckIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the policy-check integration test")
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

	org, flow, env, trail := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description,tags) VALUES ($1,$2,'f','', '{"risk":"low"}')`, flow, org)
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, env, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	mustExec(t, pool, `INSERT INTO attestations (trail_id,name,type_name,payload,is_compliant) VALUES ($1,'ut','junit','{}',true)`, trail)
	// policies: junit always required; snyk always required (missing); change required only if risk==high (won't apply).
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types) VALUES ($1,'tests',$2)`, env, pq.StringArray([]string{"junit"}))
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types) VALUES ($1,'security',$2)`, env, pq.StringArray([]string{"snyk"}))
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types,if_tag,if_value) VALUES ($1,'high-risk-change',$2,'risk','high')`, env, pq.StringArray([]string{"servicenow-change"}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/x?trail="+trail.String(), nil).WithContext(ctx)
	req.SetPathValue("id", env.String())
	rec := httptest.NewRecorder()
	s.handlePolicyCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy-check: %d %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Compliant bool `json:"compliant"`
		Results   []struct {
			Policy  string   `json:"policy"`
			Applies bool     `json:"applies"`
			Missing []string `json:"missing"`
		} `json:"results"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Compliant {
		t.Fatalf("overall should be non-compliant (snyk missing)")
	}
	byName := map[string]struct {
		applies bool
		missing []string
	}{}
	for _, r := range resp.Results {
		byName[r.Policy] = struct {
			applies bool
			missing []string
		}{r.Applies, r.Missing}
	}
	if r := byName["tests"]; !r.applies || len(r.missing) != 0 {
		t.Fatalf("tests policy should be satisfied: %+v", r)
	}
	if r := byName["security"]; !r.applies || len(r.missing) != 1 || r.missing[0] != "snyk" {
		t.Fatalf("security policy should be missing snyk: %+v", r)
	}
	if r := byName["high-risk-change"]; r.applies {
		t.Fatalf("conditional policy must NOT apply when risk!=high: %+v", r)
	}
}
