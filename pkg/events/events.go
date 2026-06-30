// Package events implements a transactional-outbox event core: durable,
// at-least-once delivery of integration events (webhooks, ServiceNow, CI/CD
// gates) to pluggable sinks.
//
// Producers call Enqueue within the same transaction as the change that caused
// the event, so the event is persisted atomically with that change. A
// background Dispatcher leases pending rows, delivers them to all registered
// sinks, and retries with exponential backoff until success or dead-letter.
//
// Delivery is at-least-once and fans out to every sink; a single sink failure
// retries the whole event, so sinks MUST be idempotent (e.g. key by event ID).
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Delivery statuses.
const (
	StatusPending   = "pending"
	StatusDelivered = "delivered"
	StatusDead      = "dead"
)

// Event is one outbox record.
type Event struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Type      string
	Payload   json.RawMessage
	Attempts  int
	CreatedAt time.Time
}

// Execer is satisfied by *sql.DB, *sql.Tx, and *sql.Conn, so an event can be
// enqueued either standalone or inside an existing transaction.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const insertSQL = `INSERT INTO integration_events (org_id, event_type, payload) VALUES ($1, $2, $3)`

// Enqueue writes an event to the outbox using x, which may be a *sql.Tx (to make
// the event atomic with the originating change) or a *sql.DB (standalone).
func Enqueue(ctx context.Context, x Execer, orgID uuid.UUID, eventType string, payload any) error {
	if eventType == "" {
		return errors.New("events: event type is required")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("events: marshal payload: %w", err)
	}
	if _, err := x.ExecContext(ctx, insertSQL, orgID, eventType, raw); err != nil {
		return fmt.Errorf("events: enqueue: %w", err)
	}
	return nil
}
