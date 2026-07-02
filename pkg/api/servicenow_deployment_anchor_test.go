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

func TestReferenceSysID(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"bare string", "abc123", "abc123"},
		{"reference object", map[string]any{"value": "abc123", "link": "https://x/y"}, "abc123"},
		{"nil", nil, ""},
		{"empty object", map[string]any{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := referenceSysID(tc.in); got != tc.want {
				t.Errorf("referenceSysID(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHandleServiceNowAnchorDeploymentRequiresServiceNowIntegration exercises
// the deployment-anchor endpoint against a real trail when ServiceNow has not
// been configured for the org: it must fail fast with 400 without touching
// the trail's evidence, rather than silently no-op. Gated by FIDES_TEST_DB_DSN.
func TestHandleServiceNowAnchorDeploymentRequiresServiceNowIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the deployment-anchor integration test")
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

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','deadbeef')`, trail, flow)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(deploymentAnchorReq{TrailID: trail.String(), ChangeNumber: "CHG0030192"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/servicenow/deployment-anchor", strings.NewReader(string(body))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleServiceNowAnchorDeployment(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when ServiceNow is not configured, got %d: %s", rec.Code, rec.Body.String())
	}

	// No anchor should have been recorded.
	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM deployment_anchors WHERE trail_id = $1`, trail).Scan(&n); err != nil {
		t.Fatalf("count anchors: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no deployment_anchors rows, got %d", n)
	}
}

// TestHandleServiceNowAnchorDeploymentRequiresTrailAndTarget checks the request
// validation path (no DB needed): both trail_id and one of change_number/ci
// are mandatory.
func TestHandleServiceNowAnchorDeploymentRequiresTrailAndTarget(t *testing.T) {
	s := &Server{}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: uuid.New(), Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(deploymentAnchorReq{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/servicenow/deployment-anchor", strings.NewReader(string(body))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleServiceNowAnchorDeployment(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing trail_id, got %d: %s", rec.Code, rec.Body.String())
	}
}
