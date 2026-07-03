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
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/vault"
)

func TestDeriveControlStatus(t *testing.T) {
	cases := []struct {
		name     string
		required []string
		latest   map[string]bool
		want     string
	}{
		{"no required types", nil, map[string]bool{}, "passed"},
		{"all present and compliant", []string{"junit", "trivy"}, map[string]bool{"junit": true, "trivy": true}, "passed"},
		{"one type missing", []string{"junit", "trivy"}, map[string]bool{"junit": true}, "missing"},
		{"present but non-compliant", []string{"junit"}, map[string]bool{"junit": false}, "failed"},
		{"missing outranks failed", []string{"junit", "trivy"}, map[string]bool{"junit": false}, "missing"},
	}
	for _, c := range cases {
		if got := deriveControlStatus(c.required, c.latest); got != c.want {
			t.Errorf("%s: deriveControlStatus(%v, %v) = %q, want %q", c.name, c.required, c.latest, got, c.want)
		}
	}
}

// End-to-end: a control's continuous evidence feed reflects the newest evidence
// per required type over the window. Gated by FIDES_TEST_DB_DSN.
func TestControlTimelineIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the control-timeline integration test")
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

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)

	// Control requiring junit; another requiring trivy (no evidence -> missing).
	mustExec(t, pool, `INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'C-JUNIT','Tests',ARRAY['junit'])`, uuid.New(), org)
	mustExec(t, pool, `INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'C-TRIVY','Scan',ARRAY['trivy'])`, uuid.New(), org)

	// Two junit attestations over time: an older compliant one, then a newer
	// non-compliant one — latest_status must reflect the newer (failed).
	mustExec(t, pool,
		`INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,created_at) VALUES ($1,$2,'ut','junit','{}',true, now() - interval '2 days')`,
		uuid.New(), trail)
	mustExec(t, pool,
		`INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,created_at) VALUES ($1,$2,'ut','junit','{}',false, now() - interval '1 hour')`,
		uuid.New(), trail)

	s := &Server{DB: pool, Secrets: vault.NewEnvSecretsProvider()}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/controls/timeline?days=90", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleControlTimeline(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		WindowDays int               `json:"window_days"`
		Controls   []controlTimeline `json:"controls"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byKey := map[string]controlTimeline{}
	for _, c := range resp.Controls {
		byKey[c.Control] = c
	}
	junit, ok := byKey["C-JUNIT"]
	if !ok {
		t.Fatalf("C-JUNIT control missing from timeline: %+v", resp.Controls)
	}
	if junit.LatestStatus != "failed" {
		t.Errorf("C-JUNIT latest_status = %q, want failed", junit.LatestStatus)
	}
	if len(junit.Events) != 2 {
		t.Errorf("C-JUNIT events = %d, want 2 (continuous feed)", len(junit.Events))
	}
	if trivy := byKey["C-TRIVY"]; trivy.LatestStatus != "missing" {
		t.Errorf("C-TRIVY latest_status = %q, want missing", trivy.LatestStatus)
	}
}
