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
