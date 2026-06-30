// Package db provides tenant-scoped database access for the Postgres
// Row-Level-Security (RLS) backstop. Every query that must be tenant-isolated
// runs on a connection where the `app.current_org` GUC is set to the caller's
// organization; the RLS policies in schema-rls.sql then enforce isolation in
// the database itself, independent of application-layer WHERE clauses.
package db

import (
	"context"
	"database/sql"
)

// Querier is the subset of *sql.DB / *sql.Conn / *sql.Tx used by handlers, so a
// tenant-scoped connection can be substituted transparently.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type querierCtxKey struct{}

// WithQuerier returns a context carrying a request-scoped Querier.
func WithQuerier(ctx context.Context, q Querier) context.Context {
	return context.WithValue(ctx, querierCtxKey{}, q)
}

// QuerierFromContext returns the request-scoped Querier, if one was set.
func QuerierFromContext(ctx context.Context) (Querier, bool) {
	q, ok := ctx.Value(querierCtxKey{}).(Querier)
	return q, ok
}

// setOrgGUC sets the tenant GUC on the given connection. It uses set_config so
// the value can be passed as a bind parameter (SET does not accept parameters).
func setOrgGUC(ctx context.Context, conn *sql.Conn, org string) error {
	_, err := conn.ExecContext(ctx, "SELECT set_config('app.current_org', $1, false)", org)
	return err
}

// ScopedConn pins a pooled connection and sets app.current_org to org for its
// lifetime. The caller MUST invoke the returned release function (e.g. via
// defer) to clear the GUC and return the connection to the pool — otherwise the
// tenant scope could leak to the next request that reuses the connection.
func ScopedConn(ctx context.Context, pool *sql.DB, org string) (*sql.Conn, func(), error) {
	conn, err := pool.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := setOrgGUC(ctx, conn, org); err != nil {
		conn.Close()
		return nil, nil, err
	}
	release := func() {
		// Best-effort reset on a fresh context so cancellation of the request
		// context cannot skip the cleanup, then return the conn to the pool.
		_, _ = conn.ExecContext(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Close()
	}
	return conn, release, nil
}

// WithOrgScope runs fn inside a transaction with app.current_org set via
// SET LOCAL, which is automatically scoped to the transaction and discarded on
// commit/rollback. Prefer this for self-contained units of work (e.g. a
// background goroutine) that do not span external I/O.
func WithOrgScope(ctx context.Context, pool *sql.DB, org string, fn func(*sql.Tx) error) error {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_org', $1, true)", org); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
