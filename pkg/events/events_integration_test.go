package events

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Requires a real Postgres (superuser DSN). Skipped unless FIDES_TEST_DB_DSN is
// set. See pkg/db for the Docker setup.
func openTestDB(t *testing.T) (*sql.DB, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run events integration tests")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := pool.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	org := uuid.New()
	if _, err := pool.Exec(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "events-"+org.String()[:8]); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(`DELETE FROM organizations WHERE id = $1`, org)
		pool.Close()
	})
	return pool, org
}

func statusOf(t *testing.T, pool *sql.DB, org uuid.UUID) (string, int) {
	t.Helper()
	var status string
	var attempts int
	if err := pool.QueryRow(
		`SELECT status, attempts FROM integration_events WHERE org_id = $1 ORDER BY created_at DESC LIMIT 1`, org,
	).Scan(&status, &attempts); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return status, attempts
}

func TestEnqueueAndDeliverIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx := context.Background()

	if err := Enqueue(ctx, pool, org, "snapshot.noncompliant", map[string]any{"service": "payments"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := Enqueue(ctx, pool, org, "attestation.reported", map[string]any{"name": "sbom"}); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}

	sink := &recordingSink{name: "rec"}
	d := NewDispatcher(pool, sink)

	n, err := d.DispatchBatch(ctx)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 events processed, got %d", n)
	}
	if sink.count() != 2 {
		t.Fatalf("sink should have received 2 events, got %d", sink.count())
	}

	var delivered int
	if err := pool.QueryRow(`SELECT count(*) FROM integration_events WHERE org_id = $1 AND status = 'delivered'`, org).Scan(&delivered); err != nil {
		t.Fatalf("count delivered: %v", err)
	}
	if delivered != 2 {
		t.Fatalf("expected 2 delivered, got %d", delivered)
	}
}

func TestRetryThenDeadLetterIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx := context.Background()

	if err := Enqueue(ctx, pool, org, "always.fails", map[string]any{"x": 1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// A sink that always fails, with a low attempt ceiling and tiny backoff.
	failing := &recordingSink{name: "bad", failFirst: 1 << 30}
	d := NewDispatcher(pool, failing)
	d.MaxAttempts = 3
	d.BaseBackoff = time.Millisecond

	// Attempt 1 -> pending (attempts=1).
	if _, err := d.DispatchBatch(ctx); err != nil {
		t.Fatalf("dispatch 1: %v", err)
	}
	if s, a := statusOf(t, pool, org); s != StatusPending || a != 1 {
		t.Fatalf("after attempt 1 expected pending/1, got %s/%d", s, a)
	}

	// Force due, attempt 2 -> still pending (attempts=2).
	makeDue(t, pool, org)
	if _, err := d.DispatchBatch(ctx); err != nil {
		t.Fatalf("dispatch 2: %v", err)
	}
	if s, a := statusOf(t, pool, org); s != StatusPending || a != 2 {
		t.Fatalf("after attempt 2 expected pending/2, got %s/%d", s, a)
	}

	// Force due, attempt 3 -> dead (attempts=3, hits MaxAttempts).
	makeDue(t, pool, org)
	if _, err := d.DispatchBatch(ctx); err != nil {
		t.Fatalf("dispatch 3: %v", err)
	}
	if s, a := statusOf(t, pool, org); s != StatusDead || a != 3 {
		t.Fatalf("after attempt 3 expected dead/3, got %s/%d", s, a)
	}

	// A dead event is not re-claimed.
	makeDue(t, pool, org)
	n, _ := d.DispatchBatch(ctx)
	if n != 0 {
		t.Fatalf("dead events must not be re-dispatched, processed %d", n)
	}
}

func makeDue(t *testing.T, pool *sql.DB, org uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(`UPDATE integration_events SET next_attempt_at = now() WHERE org_id = $1 AND status = 'pending'`, org); err != nil {
		t.Fatalf("make due: %v", err)
	}
}
