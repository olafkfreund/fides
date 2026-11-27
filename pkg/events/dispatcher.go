package events

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Sink receives delivered events. Implementations (webhooks, ServiceNow, CI/CD
// gates) should deduplicate by Event.DeliveryID across retries.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, ev Event) error
}

// Dispatcher polls the outbox and delivers due events to all sinks.
type Dispatcher struct {
	db    *sql.DB
	sinks []Sink

	BatchSize   int
	MaxAttempts int
	Interval    time.Duration // poll interval
	BaseBackoff time.Duration // first retry delay; doubles each attempt
	MaxBackoff  time.Duration
	LeaseFor    time.Duration // how long a claimed delivery is hidden from other workers
}

// NewDispatcher builds a Dispatcher with sensible defaults.
func NewDispatcher(db *sql.DB, sinks ...Sink) *Dispatcher {
	return &Dispatcher{
		db:          db,
		sinks:       sinks,
		BatchSize:   50,
		MaxAttempts: 8,
		Interval:    5 * time.Second,
		BaseBackoff: 10 * time.Second,
		MaxBackoff:  1 * time.Hour,
		LeaseFor:    1 * time.Minute,
	}
}

// backoff returns the delay before the next attempt (after `attempts` failures).
func (d *Dispatcher) backoff(attempts int) time.Duration {
	delay := d.BaseBackoff
	for i := 1; i < attempts && delay < d.MaxBackoff; i++ {
		delay *= 2
	}
	return min(delay, d.MaxBackoff)
}

// Run polls until ctx is cancelled. With no sinks registered it idles, leaving
// events pending until a consumer is added.
func (d *Dispatcher) Run(ctx context.Context) {
	if len(d.sinks) == 0 {
		log.Printf("events: dispatcher started with no sinks; events will accumulate until a sink is registered")
	}
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if len(d.sinks) == 0 {
				continue
			}
			if n, err := d.DispatchBatch(ctx); err != nil {
				log.Printf("events: dispatch batch error: %v", err)
			} else if n > 0 {
				log.Printf("events: processed %d delivery result(s)", n)
			}
		}
	}
}

// Mark each parent scheduled atomically with creating its entire delivery set.
const scheduleSQL = `
WITH unscheduled AS (
    SELECT e.id, e.attempts, e.next_attempt_at
    FROM integration_events e
    WHERE e.status = 'pending' AND e.next_attempt_at <= now()
      AND NOT e.deliveries_scheduled
    ORDER BY e.created_at, e.id
    LIMIT $2 FOR UPDATE OF e SKIP LOCKED
), scheduled AS (
    UPDATE integration_events e SET deliveries_scheduled = true
    FROM unscheduled u WHERE e.id = u.id
    RETURNING e.id, e.attempts, e.next_attempt_at
)
INSERT INTO integration_event_deliveries(event_id, sink, attempts, next_attempt_at)
SELECT e.id, s.name, e.attempts, e.next_attempt_at
FROM scheduled e CROSS JOIN unnest($1::text[]) AS s(name)`

const claimSQL = `
WITH due AS (
    SELECT d.event_id, d.sink, d.attempts
    FROM integration_event_deliveries d
    WHERE d.status = 'pending' AND d.next_attempt_at <= now()
      AND d.sink = ANY($1::text[])
    ORDER BY d.next_attempt_at, d.event_id, d.sink
    LIMIT 1 FOR UPDATE SKIP LOCKED
)
UPDATE integration_event_deliveries d
SET lease_token = $2, next_attempt_at = now() + ($3 * interval '1 microsecond'),
    attempts = d.attempts + (d.attempts < $4)::int
FROM due, integration_events e
WHERE d.event_id = due.event_id AND d.sink = due.sink AND e.id = d.event_id
RETURNING e.id, e.org_id, e.event_type, e.payload, d.attempts, e.created_at, d.sink, due.attempts < $4`

// DispatchBatch processes at most BatchSize deliveries. Each lease starts just
// before its send so time spent on earlier sends cannot expire it.
func (d *Dispatcher) DispatchBatch(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(d.sinks) == 0 {
		return 0, nil
	}
	sinks := make(map[string]Sink, len(d.sinks))
	names := make([]string, 0, len(d.sinks))
	for _, sink := range d.sinks {
		name := sink.Name()
		if _, exists := sinks[name]; name == "" || exists {
			return 0, fmt.Errorf("events: invalid or duplicate sink name %q", name)
		}
		sinks[name] = sink
		names = append(names, name)
	}
	if d.LeaseFor < 2*time.Microsecond {
		return 0, fmt.Errorf("events: lease must be at least two microseconds")
	}
	if _, err := d.db.ExecContext(ctx, scheduleSQL, pq.Array(names), d.BatchSize); err != nil {
		return 0, fmt.Errorf("schedule deliveries: %w", err)
	}
	for n := 0; n < d.BatchSize; n++ {
		deadline := time.Now().Add(min(30*time.Second, d.LeaseFor/2))
		ev, name, token, send, err := d.claim(ctx, names)
		if errors.Is(err, sql.ErrNoRows) {
			return n, nil
		}
		if err != nil {
			return n, fmt.Errorf("claim delivery: %w", err)
		}
		// A worker may have lost its last acknowledgement. Reclaim it to
		// settle the exhausted delivery without starting another send.
		sendErr := errors.New("last delivery attempt expired without acknowledgement")
		if send {
			sendCtx, cancel := context.WithDeadline(ctx, deadline)
			sendErr = sendCtx.Err()
			if sendErr == nil {
				sendErr = sinks[name].Deliver(sendCtx, ev)
			}
			cancel()
		}
		if err := d.recordResult(ctx, ev, name, token, sendErr); err != nil {
			return n, fmt.Errorf("record delivery %s: %w", ev.DeliveryID, err)
		}
	}
	return d.BatchSize, nil
}

func (d *Dispatcher) claim(ctx context.Context, names []string) (Event, string, uuid.UUID, bool, error) {
	var ev Event
	var name string
	var send bool
	token := uuid.New()
	err := d.db.QueryRowContext(ctx, claimSQL, pq.Array(names), token, d.LeaseFor.Microseconds(), d.MaxAttempts).
		Scan(&ev.ID, &ev.OrgID, &ev.Type, &ev.Payload, &ev.Attempts, &ev.CreatedAt, &name, &send)
	ev.DeliveryID = ev.ID.String() + "/" + name
	return ev, name, token, send, err
}

func (d *Dispatcher) recordResult(ctx context.Context, ev Event, sink string, token uuid.UUID, sendErr error) error {
	status := StatusDelivered
	var lastError any
	var delay time.Duration
	if sendErr != nil {
		lastError = sendErr.Error()
		status = StatusDead
		if ev.Attempts < d.MaxAttempts {
			status = StatusPending
			delay = d.backoff(ev.Attempts)
			if delay > 0 {
				delay -= rand.N(delay/2 + 1) // #nosec G404 -- retry jitter does not require cryptographic randomness.
			}
		}
	}

	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize sibling results before taking the snapshot for aggregation.
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT id FROM integration_events WHERE id = $1 FOR UPDATE`, ev.ID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE integration_event_deliveries
SET status = $4, last_error = $5, lease_token = NULL,
    next_attempt_at = clock_timestamp() + ($6 * interval '1 microsecond')
WHERE event_id = $1 AND sink = $2 AND lease_token = $3
  AND status = 'pending' AND next_attempt_at > clock_timestamp()`,
		ev.ID, sink, token, status, lastError, delay.Microseconds())
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed == 0 {
		return err
	}
	_, err = tx.ExecContext(ctx, `
WITH summary AS (
    SELECT CASE WHEN bool_or(status = 'pending') THEN 'pending'
                WHEN bool_or(status = 'dead') THEN 'dead'
                ELSE 'delivered' END AS status,
           max(attempts) AS attempts, max(last_error) AS last_error,
           min(next_attempt_at) FILTER (WHERE status = 'pending') AS next_attempt_at
    FROM integration_event_deliveries WHERE event_id = $1
)
UPDATE integration_events e
SET status = s.status, attempts = s.attempts, last_error = s.last_error,
    delivered_at = CASE WHEN s.status = 'delivered' THEN now() END,
    next_attempt_at = COALESCE(s.next_attempt_at, e.next_attempt_at)
FROM summary s WHERE e.id = $1`, ev.ID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if status == StatusDead {
		log.Printf("events: delivery %s dead-lettered after %d attempts: %v", ev.DeliveryID, ev.Attempts, sendErr)
	}
	return nil
}
