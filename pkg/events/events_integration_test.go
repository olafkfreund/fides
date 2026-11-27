package events

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"fides/pkg/db"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
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
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
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

	// Model a pending event with legacy retries and terminal rows left by the
	// old dispatcher. Only the pending events should acquire deliveries.
	if _, err := pool.Exec(`UPDATE integration_events SET attempts = 2 WHERE org_id = $1 AND event_type = 'snapshot.noncompliant'`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(`INSERT INTO integration_events (org_id, event_type, payload, status, attempts)
		VALUES ($1, 'legacy', '{}', 'delivered', 4), ($1, 'legacy', '{}', 'dead', 8)`, org); err != nil {
		t.Fatal(err)
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
	if err := pool.QueryRow(`SELECT count(*) FROM integration_events WHERE org_id = $1 AND status = 'delivered' AND deliveries_scheduled`, org).Scan(&delivered); err != nil {
		t.Fatalf("count delivered: %v", err)
	}
	if delivered != 2 {
		t.Fatalf("expected 2 delivered, got %d", delivered)
	}
	var retried, terminal int
	if err := pool.QueryRow(`SELECT
		count(*) FILTER (WHERE event_type = 'snapshot.noncompliant' AND attempts = 3),
		count(*) FILTER (WHERE event_type = 'legacy' AND NOT deliveries_scheduled AND
			(status, attempts) IN (('delivered', 4), ('dead', 8)))
		FROM integration_events WHERE org_id = $1`, org).Scan(&retried, &terminal); err != nil || retried != 1 || terminal != 2 {
		t.Fatalf("legacy rows: retried=%d terminal=%d err=%v", retried, terminal, err)
	}
}

func TestRetryThenDeadLetterIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx := context.Background()

	if err := Enqueue(ctx, pool, org, "always.fails", map[string]any{"x": 1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// A sink that always fails, with a low attempt ceiling.
	failing := &recordingSink{name: "bad", failFirst: 1 << 30}
	d := NewDispatcher(pool, failing)
	d.MaxAttempts = 3
	d.BaseBackoff = time.Minute

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
	if _, err := pool.Exec(`UPDATE integration_event_deliveries d SET next_attempt_at = now() FROM integration_events e WHERE e.id = d.event_id AND e.org_id = $1 AND d.status = 'pending'`, org); err != nil {
		t.Fatalf("make due: %v", err)
	}
}

type integrationSink struct {
	name string
	send func(context.Context, Event) error
}

func (s integrationSink) Name() string { return s.name }
func (s integrationSink) Deliver(ctx context.Context, ev Event) error {
	return s.send(ctx, ev)
}

func TestIndependentDeliveryAndFrozenSinksIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx := context.Background()
	if err := Enqueue(ctx, pool, org, "snapshot.reported", nil); err != nil {
		t.Fatal(err)
	}
	if n, err := NewDispatcher(pool).DispatchBatch(ctx); n != 0 || err != nil {
		t.Fatalf("empty dispatcher: %d, %v", n, err)
	}
	var scheduled bool
	if err := pool.QueryRow(`SELECT deliveries_scheduled FROM integration_events WHERE org_id = $1`, org).Scan(&scheduled); err != nil || scheduled {
		t.Fatalf("scheduled with no sinks: %v, %v", scheduled, err)
	}

	ok := &recordingSink{name: "ok"}
	bad := &recordingSink{name: "bad", failFirst: 1}
	d := NewDispatcher(pool, ok, bad)
	if n, err := d.DispatchBatch(ctx); n != 2 || err != nil {
		t.Fatalf("first dispatch: %d, %v", n, err)
	}
	if status, _ := statusOf(t, pool, org); status != StatusPending {
		t.Fatalf("event status after partial success: %s", status)
	}
	makeDue(t, pool, org)
	added := &recordingSink{name: "added"}
	if n, err := NewDispatcher(pool, ok, added).DispatchBatch(ctx); n != 0 || err != nil {
		t.Fatalf("dispatch without pending sink: %d, %v", n, err)
	}
	if n, err := d.DispatchBatch(ctx); n != 1 || err != nil {
		t.Fatalf("second dispatch: %d, %v", n, err)
	}
	if ok.count() != 1 || bad.count() != 1 || added.count() != 0 {
		t.Fatalf("successes: ok=%d bad=%d added=%d", ok.count(), bad.count(), added.count())
	}
	if status, attempts := statusOf(t, pool, org); status != StatusDelivered || attempts != 2 {
		t.Fatalf("event status after retry: %s/%d", status, attempts)
	}
}

func TestDeliveryLeaseAndLostAcknowledgementIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Enqueue(ctx, pool, org, "snapshot.reported", nil); err != nil {
		t.Fatal(err)
	}
	applied := map[string]bool{}
	sends, sideEffects := 0, 0
	sink := integrationSink{"idempotent", func(ctx context.Context, ev Event) error {
		sends++
		if ev.DeliveryID != ev.ID.String()+"/idempotent" {
			t.Fatalf("invalid delivery identity: %q", ev.DeliveryID)
		}
		if !applied[ev.DeliveryID] {
			sideEffects++
			applied[ev.DeliveryID] = true
		}
		return nil
	}}
	sibling := &recordingSink{name: "lease-sibling", failFirst: 1}
	d := NewDispatcher(pool, sink, sibling)
	siblingWorker := NewDispatcher(pool, sibling)
	siblingWorker.BaseBackoff = time.Minute
	names := []string{sink.Name()}
	if _, err := pool.ExecContext(ctx, scheduleSQL, pq.Array([]string{sink.Name(), sibling.Name()}), 1); err != nil {
		t.Fatal(err)
	}
	old, name, token, send, err := d.claim(ctx, names)
	if err != nil || !send {
		t.Fatalf("claim: send=%v err=%v", send, err)
	}
	if err := sink.Deliver(ctx, old); err != nil {
		t.Fatal(err)
	}
	makeDue(t, pool, org)
	type claimResult struct {
		event Event
		token uuid.UUID
		send  bool
		err   error
	}
	ready := make(chan struct{})
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for range 2 {
		worker := NewDispatcher(pool, sink)
		go func() {
			ready <- struct{}{}
			<-start
			event, _, token, send, err := worker.claim(ctx, names)
			results <- claimResult{event, token, send, err}
		}()
	}
	for range 2 {
		<-ready
	}
	close(start)
	var winner claimResult
	wins := 0
	for range 2 {
		result := <-results
		if errors.Is(result.err, sql.ErrNoRows) {
			continue
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		wins++
		winner = result
	}
	current, currentToken := winner.event, winner.token
	if wins != 1 || !winner.send || currentToken == token || current.DeliveryID != old.DeliveryID {
		t.Fatalf("reclaim: winners=%d attempt=%d send=%v", wins, current.Attempts, winner.send)
	}
	var leaseUntil time.Time
	if err := pool.QueryRowContext(ctx, `SELECT next_attempt_at FROM integration_event_deliveries
		WHERE event_id = $1 AND sink = $2`, old.ID, name).Scan(&leaseUntil); err != nil {
		t.Fatal(err)
	}
	if n, err := siblingWorker.DispatchBatch(ctx); n != 1 || err != nil {
		t.Fatalf("sibling first attempt: %d, %v", n, err)
	}
	var siblingBackedOff bool
	if err := pool.QueryRowContext(ctx, `SELECT status = 'pending' AND attempts = 1
		AND lease_token IS NULL AND last_error IS NOT NULL AND next_attempt_at > now()
		FROM integration_event_deliveries WHERE event_id = $1 AND sink = $2`,
		old.ID, sibling.Name()).Scan(&siblingBackedOff); err != nil || !siblingBackedOff {
		t.Fatalf("sibling backed off after first attempt: %v, %v", siblingBackedOff, err)
	}

	if err := d.recordResult(ctx, old, name, token, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.recordResult(ctx, old, name, token, errors.New("stale result")); err != nil {
		t.Fatal(err)
	}
	if status, _ := statusOf(t, pool, org); status != StatusPending {
		t.Fatalf("stale result changed parent to %s", status)
	}
	if _, err := pool.ExecContext(ctx, `UPDATE integration_event_deliveries SET next_attempt_at = now()
		WHERE event_id = $1 AND sink = $2`, old.ID, sibling.Name()); err != nil {
		t.Fatal(err)
	}
	if n, err := d.DispatchBatch(ctx); n != 1 || err != nil {
		t.Fatalf("sibling retry while reclaimed lease is active: %d, %v", n, err)
	}
	var winnerOwnsLease, siblingDelivered bool
	if err := pool.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM integration_event_deliveries WHERE event_id = $1 AND sink = $2
			AND status = 'pending' AND attempts = 2 AND lease_token = $3 AND next_attempt_at = $4
			AND last_error IS NULL),
		EXISTS (SELECT 1 FROM integration_event_deliveries WHERE event_id = $1 AND sink = $5
			AND status = 'delivered' AND attempts = 2 AND lease_token IS NULL AND last_error IS NULL)`,
		old.ID, name, currentToken, leaseUntil, sibling.Name()).Scan(&winnerOwnsLease, &siblingDelivered); err != nil ||
		!winnerOwnsLease || !siblingDelivered || sibling.count() != 1 {
		t.Fatalf("after stale results and sibling retry: winner owns unchanged lease=%v sibling delivered=%v sibling successes=%d err=%v",
			winnerOwnsLease, siblingDelivered, sibling.count(), err)
	}
	if status, attempts := statusOf(t, pool, org); status != StatusPending || attempts != 2 {
		t.Fatalf("event after sibling retry: %s/%d", status, attempts)
	}
	if err := sink.Deliver(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := d.recordResult(ctx, current, name, currentToken, nil); err != nil {
		t.Fatal(err)
	}
	if sends != 2 || sideEffects != 1 {
		t.Fatalf("sends=%d unique applications=%d", sends, sideEffects)
	}
	if status, attempts := statusOf(t, pool, org); status != StatusDelivered || attempts != 2 {
		t.Fatalf("event after reclaim: %s/%d", status, attempts)
	}
}

func TestDeliveryTimeoutAndSiblingResultsIntegration(t *testing.T) {
	pool, org := openTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Enqueue(ctx, pool, org, "snapshot.reported", nil); err != nil {
		t.Fatal(err)
	}
	started := make(chan time.Duration, 1)
	slow := integrationSink{"slow", func(ctx context.Context, _ Event) error {
		deadline, _ := ctx.Deadline()
		started <- time.Until(deadline)
		<-ctx.Done()
		return ctx.Err()
	}}
	ok := &recordingSink{name: "ok"}
	d := NewDispatcher(pool, slow, ok)
	d.LeaseFor = time.Second
	d.MaxAttempts = 1
	names := []string{slow.Name(), ok.Name()}
	if _, err := pool.ExecContext(ctx, scheduleSQL, pq.Array(names), 1); err != nil {
		t.Fatal(err)
	}
	// Separate workers settle siblings on the same parent.
	results := make(chan error, 2)
	for _, sink := range []Sink{slow, ok} {
		worker := NewDispatcher(pool, sink)
		worker.LeaseFor = d.LeaseFor
		worker.MaxAttempts = d.MaxAttempts
		go func() {
			n, err := worker.DispatchBatch(ctx)
			if err == nil && n != 1 {
				err = fmt.Errorf("processed %d deliveries, want 1", n)
			}
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case budget := <-started:
		if budget <= 0 || budget > d.LeaseFor/2 {
			t.Fatalf("unexpected send budget: %v", budget)
		}
	default:
		t.Fatal("timed sink was never called")
	}
	if status, attempts := statusOf(t, pool, org); status != StatusDead || attempts != 1 || ok.count() != 1 {
		t.Fatalf("event after sibling results: %s/%d, successful deliveries %d", status, attempts, ok.count())
	}
}
