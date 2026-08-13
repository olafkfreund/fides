package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestIntegrationScopedConnPoisonedByCancel pins down the mechanism behind the
// production "sql: connection is already closed" reports (issue #405).
//
// lib/pq's watchCancel marks a connection bad as soon as the context handed to
// a query is cancelled, and its finish func closes the underlying conn
// outright. On the RLS path that connection is PINNED (ScopedConn returns a
// *sql.Conn), so there is no pool retry to hide it: the next query closes the
// *sql.Conn and every query after that fails with sql.ErrConnDone.
//
// In the server this is reached whenever an HTTP client hangs up mid-request:
// serveAuthenticated derives the scoped conn from r.Context(), so a disconnect
// poisons it. The best-effort segregation-of-duties emitter is the last DB user
// in both change-gate and approve, which is why it is where the error surfaced.
func TestIntegrationScopedConnPoisonedByCancel(t *testing.T) {
	dsn := testDSN(t)
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	// One connection, so the poisoned one is necessarily the one reused.
	pool.SetMaxOpenConns(1)

	org := "11111111-1111-1111-1111-111111111111"

	ctx, cancel := context.WithCancel(context.Background())
	conn, release, err := ScopedConn(ctx, pool, org)
	if err != nil {
		t.Fatalf("ScopedConn: %v", err)
	}
	defer release()

	// The scoped conn works while the request context is live.
	var got string
	if err := conn.QueryRowContext(ctx, "SELECT current_setting('app.current_org', true)").Scan(&got); err != nil {
		t.Fatalf("pre-cancel query: %v", err)
	}
	if got != org {
		t.Fatalf("app.current_org = %q, want %q", got, org)
	}

	// The client hangs up while a query is in flight. Cancelling between
	// queries is harmless — lib/pq's watchCancel has already been finished by
	// then — so the poisoning window is specifically "mid-query", which is
	// exactly what an HTTP disconnect produces.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	inflight := conn.QueryRowContext(ctx, "SELECT pg_sleep(5)").Scan(new(any))
	t.Logf("in-flight query at cancel: %v", inflight)
	if inflight == nil {
		t.Fatal("in-flight query returned before cancellation; test is not exercising the race")
	}

	// First query after cancellation: the driver reports the conn as bad, and
	// database/sql closes the pinned *sql.Conn as a side effect.
	first := conn.QueryRowContext(context.Background(), "SELECT 1").Scan(new(int))
	if first == nil {
		t.Skip("driver did not poison the connection on cancel; nothing to demonstrate")
	}
	t.Logf("first query after cancel: %v", first)

	// Second query: this is the production symptom. Any write attempted here —
	// e.g. a segregation-of-duties attestation — is silently lost, because the
	// emitter logs the error and returns nil so as not to fail the request.
	second := conn.QueryRowContext(context.Background(), "SELECT 1").Scan(new(int))
	t.Logf("second query after cancel: %v", second)
	if !errors.Is(second, sql.ErrConnDone) {
		t.Fatalf("second query after cancel = %v, want sql.ErrConnDone (the production symptom)", second)
	}
}
