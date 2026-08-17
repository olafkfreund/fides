package api

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// A time-boxed control exception must move a failing control from `failed` to
// `waived` in the change-gate verdict, so a held gate can proceed on a governed
// waiver — and stop applying once the waiver is revoked.
func TestChangeGateHonoursException(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the control-exception integration test")
	}
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
	mig, _ := os.ReadFile(filepath.Join("..", "..", "pkg", "db", "migrations", "0023_control_exceptions.sql"))
	if _, err := pool.Exec(string(mig)); err != nil {
		t.Fatalf("migration 0023: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	// A control requiring "junit", and a FAILING junit attestation on the trail.
	mustExec(t, pool, `INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'TEST-CTRL','Test control',$3)`,
		uuid.New(), org, pq.Array([]string{"junit"}))
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant) VALUES ($1,$2,'junit','junit','{}',false)`,
		uuid.New(), trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := context.Background()

	has := func(out map[string]any, bucket, key string) bool {
		for _, e := range out[bucket].([]map[string]any) {
			if e["control"] == key {
				return true
			}
		}
		return false
	}

	// 1) No exception -> the control FAILS.
	out, err := s.computeChangeGate(ctx, org, trail)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if !has(out, "failed", "TEST-CTRL") {
		t.Fatalf("expected TEST-CTRL failed, got %+v", out["failed"])
	}

	// 2) An in-date exception -> the control is WAIVED, not failed.
	var exID uuid.UUID
	mustExec(t, pool, `INSERT INTO control_exceptions (id,org_id,control_key,reason,expires_at) VALUES ($1,$2,'TEST-CTRL','risk accepted',$3)`,
		func() uuid.UUID { exID = uuid.New(); return exID }(), org, time.Now().Add(24*time.Hour))
	out, _ = s.computeChangeGate(ctx, org, trail)
	if has(out, "failed", "TEST-CTRL") {
		t.Fatalf("waiver ignored: TEST-CTRL still failed")
	}
	if !has(out, "waived", "TEST-CTRL") {
		t.Fatalf("expected TEST-CTRL waived, got %+v", out["waived"])
	}

	// 3) Revoked exception -> back to failed.
	mustExec(t, pool, `UPDATE control_exceptions SET revoked=true WHERE id=$1`, exID)
	out, _ = s.computeChangeGate(ctx, org, trail)
	if !has(out, "failed", "TEST-CTRL") {
		t.Fatalf("revoked waiver still applied: TEST-CTRL not failed")
	}
}
