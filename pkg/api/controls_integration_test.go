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

func TestControlsCoverageIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the controls-coverage integration test")
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

	org, env1, env2 := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s'),($3,$2,'staging','k8s')`, env1, org, env2)
	// env1 has a policy requiring junit,trivy (superset of the control's junit) -> enforces it.
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types) VALUES ($1,'p',$2)`, env1, pq.StringArray([]string{"junit", "trivy"}))
	// control requires only junit.
	mustExec(t, pool, `INSERT INTO controls (org_id,key,name,required_types) VALUES ($1,'SOC2-CC7.1','Testing',$2)`, org, pq.StringArray([]string{"junit"}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/controls/coverage", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleControlsCoverage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("coverage: %d %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		TotalEnvironments int `json:"total_environments"`
		Controls          []struct {
			Control    string   `json:"control"`
			EnforcedIn []string `json:"enforced_in"`
			Coverage   float64  `json:"coverage"`
		} `json:"controls"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.TotalEnvironments != 2 || len(resp.Controls) != 1 {
		t.Fatalf("unexpected coverage shape: %+v", resp)
	}
	c := resp.Controls[0]
	if c.Control != "SOC2-CC7.1" || len(c.EnforcedIn) != 1 || c.EnforcedIn[0] != "prod" || c.Coverage != 0.5 {
		t.Fatalf("coverage wrong: %+v", c)
	}
	_ = env2
}
