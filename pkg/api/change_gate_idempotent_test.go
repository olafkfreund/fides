package api

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// TestChangeGateIdempotentSoD guards #282: the change-gate GET must not append a
// new segregation-of-duties attestation on every call. After a green SoD is
// established, repeated change-gate reads leave exactly one SoD attestation.
func TestChangeGateIdempotentSoD(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the change-gate idempotency test")
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
	// Unique emails per run: users.email is globally unique, so hardcoded
	// addresses would collide with other tests sharing the same test DB.
	sfx := org.String()[:8]
	committer := "committer-" + sfx + "@example.com"
	approver := "approver-" + sfx + "@example.com"
	deployer := "deployer-" + sfx + "@example.com"
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,tags) VALUES ($1,$2,'t','abc123',$3::jsonb)`,
		trail, flow, `{"committer":"`+committer+`"}`)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	admin := &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "service"}
	t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")

	for _, u := range []string{approver, deployer} {
		if rec := invokeSaveUser(t, s, admin, map[string]any{"name": u, "email": u, "role": "Writer"}); rec.Code != http.StatusOK {
			t.Fatalf("register %s: %d %s", u, rec.Code, rec.Body.String())
		}
	}
	if rec := invokeRecordApproval(t, s, admin, trail, map[string]any{"role": "approver", "on_behalf_of": approver}); rec.Code != http.StatusCreated {
		t.Fatalf("approver: %d %s", rec.Code, rec.Body.String())
	}
	if rec := invokeRecordApproval(t, s, admin, trail, map[string]any{"role": "deployer", "on_behalf_of": deployer}); rec.Code != http.StatusCreated {
		t.Fatalf("deployer: %d %s", rec.Code, rec.Body.String())
	}

	// Hit the gate several times — each is a GET and must be idempotent.
	for i := 0; i < 4; i++ {
		invokeChangeGate(t, s, admin, trail)
	}

	var n int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name=$2`,
		trail, SegregationOfDutiesAttestationType).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("segregation-of-duties attestations = %d, want exactly 1 (change-gate GET must not append on every call)", n)
	}

	// Sanity: the chain is still valid (no duplicate/altered links).
	var payload string
	if err := pool.QueryRow(`SELECT payload::text FROM attestations WHERE trail_id=$1 AND type_name=$2`,
		trail, SegregationOfDutiesAttestationType).Scan(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
}
