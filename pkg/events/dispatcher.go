package events

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// Sink receives delivered events. Implementations (webhooks, ServiceNow, CI/CD
// gates) MUST be idempotent — an event may be redelivered after a partial or
// failed fan-out.
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
	LeaseFor    time.Duration // how long a claimed event is hidden from other workers
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
	if delay > d.MaxBackoff {
		delay = d.MaxBackoff
	}
	return delay
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
				log.Printf("events: processed %d event(s)", n)
			}
		}
	}
}

// claimSQL atomically leases due pending events: it hides them from other
// workers for LeaseFor and returns them for delivery (FOR UPDATE SKIP LOCKED
// makes this safe across multiple dispatcher instances).
const claimSQL = `
WITH due AS (
    SELECT id FROM integration_events
    WHERE status = 'pending' AND next_attempt_at <= now()
    ORDER BY created_at
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE integration_events e
   SET next_attempt_at = now() + ($2 * interval '1 second')
  FROM due
 WHERE e.id = due.id
RETURNING e.id, e.org_id, e.event_type, e.payload, e.attempts, e.created_at`

// DispatchBatch claims a batch and delivers it. Returns the number processed.
// Exported so tests can drive a single cycle deterministically.
func (d *Dispatcher) DispatchBatch(ctx context.Context) (int, error) {
	rows, err := d.db.QueryContext(ctx, claimSQL, d.BatchSize, int(d.LeaseFor.Seconds()))
	if err != nil {
		return 0, fmt.Errorf("claim: %w", err)
	}
	var batch []Event
	for rows.Next() {
		var ev Event
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.Type, &ev.Payload, &ev.Attempts, &ev.CreatedAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		batch = append(batch, ev)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()

	for _, ev := range batch {
		if derr := d.deliver(ctx, ev); derr != nil {
			d.recordFailure(ctx, ev, derr)
		} else {
			d.recordSuccess(ctx, ev)
		}
	}
	return len(batch), nil
}

// deliver fans the event out to every sink; any failure fails the event.
func (d *Dispatcher) deliver(ctx context.Context, ev Event) error {
	var errs []error
	for _, s := range d.sinks {
		if err := s.Deliver(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("sink %s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (d *Dispatcher) recordSuccess(ctx context.Context, ev Event) {
	_, err := d.db.ExecContext(ctx,
		`UPDATE integration_events SET status = 'delivered', delivered_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1`,
		ev.ID)
	if err != nil {
		log.Printf("events: mark delivered %s: %v", ev.ID, err)
	}
}

func (d *Dispatcher) recordFailure(ctx context.Context, ev Event, derr error) {
	attempts := ev.Attempts + 1
	if attempts >= d.MaxAttempts {
		if _, err := d.db.ExecContext(ctx,
			`UPDATE integration_events SET status = 'dead', attempts = $2, last_error = $3 WHERE id = $1`,
			ev.ID, attempts, derr.Error()); err != nil {
			log.Printf("events: mark dead %s: %v", ev.ID, err)
		}
		log.Printf("events: event %s dead-lettered after %d attempts: %v", ev.ID, attempts, derr)
		return
	}
	next := d.backoff(attempts)
	if _, err := d.db.ExecContext(ctx,
		`UPDATE integration_events SET status = 'pending', attempts = $2, last_error = $3, next_attempt_at = now() + ($4 * interval '1 second') WHERE id = $1`,
		ev.ID, attempts, derr.Error(), int(next.Seconds())); err != nil {
		log.Printf("events: mark retry %s: %v", ev.ID, err)
	}
}
