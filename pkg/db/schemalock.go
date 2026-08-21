package db

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaLockID is an arbitrary but STABLE application-chosen key for the
// Postgres advisory lock that serialises schema setup. Every Fides server
// process must use the same number for the lock to mean anything; changing it
// silently disables the mutual exclusion, so do not.
const schemaLockID int64 = 8021977463119540

// WithSchemaLock runs fn while holding a session-level advisory lock, so that
// only one server process performs schema setup at a time.
//
// Without it, a rolling update has both the outgoing and incoming pod running
// migrations and the RLS policy file against the same database at once, and
// Postgres rejects the loser with
//
//	pq: tuple concurrently updated (XX000)
//
// which is fatal at startup. Observed on every sarc-aws deploy: the new pod
// crashed once, restarted, and succeeded on the retry -- self-healing, and
// therefore invisible, but it means each release has a window where the new
// pod is down for a reason unrelated to the release. It would stop being
// self-healing the moment a readiness gate or a CrashLoopBackOff threshold sat
// in front of it.
//
// pg_advisory_lock is the right primitive here rather than a table flag: it is
// held for the life of the SESSION and released automatically if the process
// dies mid-migration, so a crashed deploy cannot wedge every future boot on a
// lock nobody will ever unlock.
//
// The lock is taken on a single dedicated connection, because advisory locks
// are per-session and a pooled *sql.DB could otherwise unlock from a different
// connection than it locked on.
func WithSchemaLock(ctx context.Context, db *sql.DB, fn func(context.Context) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("schema lock: acquire connection: %w", err)
	}
	//nolint:errcheck // returning a pooled connection; the read already happened
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("schema lock: %w", err)
	}
	defer func() {
		// Best-effort: closing the connection releases the lock anyway.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", schemaLockID)
	}()

	return fn(ctx)
}
