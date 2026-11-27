package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"fides/pkg/db"
	"fides/pkg/events"

	"github.com/google/uuid"
)

const craReminderLeadTime = time.Hour

// RunCRAReminders queues deadline events until the server context is cancelled.
func RunCRAReminders(ctx context.Context, pool *sql.DB, now func() time.Time) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := sweepCRAReminders(ctx, pool, now()); err != nil && ctx.Err() == nil {
			log.Printf("CRA reminder sweep: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sweepCRAReminders(ctx context.Context, pool *sql.DB, now time.Time) error {
	var orgs []uuid.UUID
	if err := db.WithOrgScope(ctx, pool, "", func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT org_id FROM cra_reminder_orgs`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var orgID uuid.UUID
			if err := rows.Scan(&orgID); err != nil {
				return err
			}
			orgs = append(orgs, orgID)
		}
		return rows.Err()
	}); err != nil {
		return fmt.Errorf("list reminder tenants: %w", err)
	}

	var sweepErr error
	for _, orgID := range orgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := enqueueCRAOrgReminders(ctx, pool, orgID, now); err != nil {
			sweepErr = errors.Join(sweepErr, fmt.Errorf("queue reminders for tenant %s: %w", orgID, err))
		}
	}
	return sweepErr
}

// Lock the revision so a concurrent sweep, correction or submission cannot
// change eligibility between selecting it and committing its outbox event.
const claimCRAReminders = `
WITH eligible AS (
    SELECT case_id, stage, revision, due_at <= $2 AS overdue
    FROM cra_case_deadlines
    WHERE org_id = $1 AND superseded_at IS NULL AND satisfied_at IS NULL
      AND overdue_enqueued_at IS NULL AND due_at <= $3
      AND (due_at <= $2 OR due_soon_enqueued_at IS NULL)
    ORDER BY due_at, case_id, stage, revision
    LIMIT 100 FOR UPDATE SKIP LOCKED
)
UPDATE cra_case_deadlines d
SET due_soon_enqueued_at = CASE WHEN e.overdue THEN d.due_soon_enqueued_at ELSE $2 END,
    overdue_enqueued_at = CASE WHEN e.overdue THEN $2 ELSE d.overdue_enqueued_at END
FROM eligible e
WHERE d.org_id = $1 AND (d.case_id, d.stage, d.revision) = (e.case_id, e.stage, e.revision)
RETURNING d.case_id, d.stage, d.revision, d.due_at, e.overdue`

func enqueueCRAOrgReminders(ctx context.Context, pool *sql.DB, orgID uuid.UUID, now time.Time) error {
	return db.WithOrgScope(ctx, pool, orgID.String(), func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, claimCRAReminders, orgID, now, now.Add(craReminderLeadTime))
		if err != nil {
			return err
		}
		defer rows.Close()
		type reminder struct {
			events.CRADeadline
			overdue bool
		}
		var batch []reminder
		for rows.Next() {
			var r reminder
			if err := rows.Scan(&r.CaseID, &r.Stage, &r.Revision, &r.DueAt, &r.overdue); err != nil {
				return err
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range batch {
			eventType := events.CRADeadlineDueSoon
			if r.overdue {
				eventType = events.CRADeadlineOverdue
			}
			r.DueAt = r.DueAt.UTC()
			if err := events.Enqueue(ctx, tx, orgID, eventType, r.CRADeadline); err != nil {
				return err
			}
		}
		return nil
	})
}
