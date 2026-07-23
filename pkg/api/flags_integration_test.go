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
	"github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/ledger"
)

// TestRecordFlagChange checks the feature-flag governance core bridge (#287): a
// flag change is recorded as a flag.changed attestation on an auto-created
// per-change trail, chained into the ledger, and the "feature-flags" flow is
// find-or-created (reused across changes).
func TestRecordFlagChange(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the flag-change bridge test")
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

	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	record := func(key, env, from, to string) map[string]any {
		body, _ := json.Marshal(map[string]any{
			"flag_key": key, "environment": env, "old_state": from, "new_state": to,
			"actor": "olaf@acme.com", "source": "unleash",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/flags/changed", strings.NewReader(string(body))).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleRecordFlagChange(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("record flag change: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	out1 := record("checkout-v2", "prod", "off", "on")
	record("new-pricing", "prod", "on", "off")

	// The org's flag-change flow is find-or-created (exactly one).
	var flows int
	pool.QueryRow(`SELECT count(*) FROM flows WHERE org_id=$1 AND name=$2`, org, flagFlowName).Scan(&flows)
	if flows != 1 {
		t.Fatalf("feature-flags flows = %d, want 1 (find-or-create)", flows)
	}

	// Two per-change trails, each with a chained flag.changed attestation.
	var trails, atts, chained int
	pool.QueryRow(`SELECT count(*) FROM trails tr JOIN flows f ON f.id=tr.flow_id WHERE f.org_id=$1 AND f.name=$2`, org, flagFlowName).Scan(&trails)
	pool.QueryRow(`SELECT count(*), count(content_hash) FROM attestations WHERE type_name=$1`, FlagChangedAttestationType).Scan(&atts, &chained)
	if trails != 2 || atts != 2 || chained != 2 {
		t.Fatalf("trails=%d attestations=%d chained=%d, want 2/2/2", trails, atts, chained)
	}

	// The first change's trail chain verifies, and its payload round-trips.
	trailID := uuid.MustParse(out1["trail_id"].(string))
	var payload string
	if err := pool.QueryRow(`SELECT payload::text FROM attestations WHERE trail_id=$1 AND type_name=$2`,
		trailID, FlagChangedAttestationType).Scan(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	var p struct {
		FlagKey     string `json:"flag_key"`
		Environment string `json:"environment"`
		OldState    string `json:"old_state"`
		NewState    string `json:"new_state"`
		Source      string `json:"source"`
	}
	if err := json.Unmarshal([]byte(ledger.CanonicalJSON(payload)), &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.FlagKey != "checkout-v2" || p.Environment != "prod" || p.NewState != "on" || p.Source != "unleash" {
		t.Fatalf("payload = %+v, want checkout-v2/prod/on/unleash", p)
	}
}

// TestFlagChangePolicyCompliance checks that JQ rules registered for the
// flag.changed attestation type govern compliance (#288): a flag change that
// violates the rule is recorded non-compliant (and so fails the change gate).
func TestFlagChangePolicyCompliance(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the flag-change policy test")
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

	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	// Governance policy: a flag change must name an actor to be compliant.
	mustExec(t, pool, `INSERT INTO attestation_types (id,org_id,name,jq_rules) VALUES ($1,$2,$3,$4)`,
		uuid.New(), org, FlagChangedAttestationType, pq.Array([]string{`.actor != ""`}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	rec := func(actor string) bool {
		body, _ := json.Marshal(map[string]any{"flag_key": "k", "environment": "prod", "new_state": "on", "actor": actor})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/flags/changed", strings.NewReader(string(body))).WithContext(ctx)
		w := httptest.NewRecorder()
		s.handleRecordFlagChange(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("record: %d %s", w.Code, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		var compliant bool
		pool.QueryRow(`SELECT is_compliant FROM attestations WHERE id=$1`, out["attestation_id"]).Scan(&compliant)
		return compliant
	}

	if rec("") {
		t.Fatal("flag change with no actor should be non-compliant (violates .actor != \"\")")
	}
	if !rec("olaf@acme.com") {
		t.Fatal("flag change with an actor should be compliant")
	}
}

// TestFlagChangeRejectsForeignFlow guards the tenant boundary: a caller must not
// be able to record a flag change into another org's flow via a request-body
// flow_id.
func TestFlagChangeRejectsForeignFlow(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the flag-change cross-org test")
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

	orgA, orgB, flowB := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)`, orgA, "a-"+orgA.String()[:8], orgB, "b-"+orgB.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'victim','')`, flowB, orgB)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: orgA, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(map[string]any{"flag_key": "evil", "flow_id": flowB.String(), "new_state": "on"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flags/changed", strings.NewReader(string(body))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleRecordFlagChange(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatalf("expected rejection when writing into another org's flow, got 201")
	}
	// Nothing should have been written under org B's flow.
	var trails int
	pool.QueryRow(`SELECT count(*) FROM trails WHERE flow_id=$1`, flowB).Scan(&trails)
	if trails != 0 {
		t.Fatalf("a trail was injected into org B's flow: %d", trails)
	}
}
