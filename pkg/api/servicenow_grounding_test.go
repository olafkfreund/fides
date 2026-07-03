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
)

// handleServiceNowGrounding returns an authoritative grounding pack for a change
// that has Fides evidence linked, and a clear "unverified" 404 for one that
// doesn't. Gated by FIDES_TEST_DB_DSN.
func TestServiceNowGroundingIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the grounding integration test")
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
	control, att := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	mustExec(t, pool, `INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'SOC2-CC8.1','Tests',ARRAY['junit'])`, control, org)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant) VALUES ($1,$2,'ut','junit','{}',true)`, att, trail)
	mustExec(t, pool,
		`INSERT INTO change_control_links (org_id,trail_id,control_id,attestation_id,change_number,linked_by) VALUES ($1,$2,$3,$4,'CHG0030192','ci@x')`,
		org, trail, control, att)

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	// Linked change -> grounded pack.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servicenow/grounding?change=CHG0030192", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleServiceNowGrounding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("linked change: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var pack struct {
		ChangeNumber     string `json:"change_number"`
		Grounded         bool   `json:"grounded"`
		ControlsLinked   []map[string]any
		Coverage         map[string]any `json:"coverage"`
		GroundingSummary string         `json:"grounding_summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pack.Grounded {
		t.Errorf("expected grounded=true for a linked change")
	}
	if pack.Coverage["satisfied"].(float64) != 1 {
		t.Errorf("expected 1 satisfied control, got %v", pack.Coverage["satisfied"])
	}
	if pack.GroundingSummary == "" || pack.ChangeNumber != "CHG0030192" {
		t.Errorf("bad grounding pack: %+v", pack)
	}

	// Unlinked change -> 404 + unverified summary.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/servicenow/grounding?change=CHG9999999", nil).WithContext(ctx)
	rec2 := httptest.NewRecorder()
	s.handleServiceNowGrounding(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("unlinked change: HTTP %d (want 404): %s", rec2.Code, rec2.Body.String())
	}
}
