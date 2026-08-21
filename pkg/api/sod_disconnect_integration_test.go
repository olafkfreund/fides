package api

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/db"
)

// TestIntegrationSoDSurvivesClientDisconnect is the regression test for #405.
//
// Under RLS the request runs on a PINNED connection (db.ScopedConn). When the
// HTTP client hangs up mid-request, lib/pq marks that connection bad and
// database/sql closes it, so every later query on it fails with
// sql.ErrConnDone — see TestIntegrationScopedConnPoisonedByCancel in pkg/db for
// the mechanism. The segregation-of-duties emitter runs last in both
// change-gate and approve and is best-effort, so it logged the error, returned
// nil, and the attestation was lost with nothing failing.
//
// This reproduces that exact state — a cancelled request context carrying an
// already-closed scoped querier — and asserts the attestation is still written.
func TestIntegrationSoDSurvivesClientDisconnect(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the SoD disconnect regression test")
	}
	t.Setenv("FIDES_RLS_ENABLED", "true")

	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	flow := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,$3)`, flow, org, "f-"+flow.String()[:8])

	// A trail with a full, compliant set of identities, so the emitter has a
	// verdict worth recording rather than "evidence incomplete".
	trail := uuid.New()
	// trails carries no org_id — it is scoped through flow_id -> flows.org_id.
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,tags) VALUES ($1,$2,$3,$4)`,
		trail, flow, "t-"+trail.String()[:8], `{"committer":"committer@example.com"}`)
	mustExec(t, pool, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind,role) VALUES ($1,$2,$3,$4,$5)`,
		org, trail, "approver@example.com", "user", "approver")
	mustExec(t, pool, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind,role) VALUES ($1,$2,$3,$4,$5)`,
		org, trail, "deployer@example.com", "user", "deployer")

	s := &Server{DB: pool}

	// Rebuild the production failure state: a scoped conn pinned to the request
	// context, then the client disconnecting.
	reqCtx, cancel := context.WithCancel(context.Background())
	conn, release, err := db.ScopedConn(reqCtx, pool, org.String())
	if err != nil {
		t.Fatalf("ScopedConn: %v", err)
	}
	defer release()
	reqCtx = db.WithQuerier(reqCtx, conn)

	// Client hangs up, and the pinned conn is closed underneath the handler.
	cancel()
	if err := conn.Close(); err != nil {
		t.Fatalf("close pinned conn: %v", err)
	}
	if err := conn.QueryRowContext(context.Background(), "SELECT 1").Scan(new(int)); !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("precondition: pinned conn error = %v, want sql.ErrConnDone", err)
	}

	// The emitter must still record the evidence. Before the fix this returned
	// nil and logged "sql: connection is already closed".
	if got := s.emitSegregationOfDutiesAttestation(reqCtx, org, trail); got == nil {
		t.Fatal("emitSegregationOfDutiesAttestation returned nil after client disconnect — attestation silently lost (#405)")
	}

	var n int
	if err := pool.QueryRow(
		`SELECT count(*) FROM attestations WHERE trail_id=$1 AND type_name=$2`,
		trail, SegregationOfDutiesAttestationType).Scan(&n); err != nil {
		t.Fatalf("count attestations: %v", err)
	}
	if n != 1 {
		t.Fatalf("segregation-of-duties attestations = %d, want 1 (evidence must survive a client disconnect)", n)
	}
}
