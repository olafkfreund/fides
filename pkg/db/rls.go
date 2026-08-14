package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
)

// rlsSchema is kept BYTE-IDENTICAL to the repo-root schema-rls.sql, the same
// way migrations/0001_init.sql mirrors schema.sql. Enforced by a unit test.
//
//go:embed schema-rls.sql
var rlsSchema string

// ApplyRLS applies the row-level-security policies to an existing database.
//
// Deliberately NOT a numbered migration. schema-rls.sql is idempotent and must
// re-run whenever it CHANGES: it both installs the tenant_isolation policies and
// self-heals databases that got an earlier version of them. A numbered migration
// runs once and is never revisited, so an edit to the policy set would never
// reach a database that had already run it.
//
// That is not hypothetical. Until this existed, nothing applied the file at all
// -- it was a manual step referenced only from comments and docs. The AWS
// deployment consequently sat on an older policy set that still had
// tenant_isolation on service_accounts / service_account_keys, so the pre-auth
// API-key lookup (which runs before the tenant is known, with no app.current_org)
// matched zero rows and EVERY service-account key failed with 401. The fix for
// that had been in the file for some time; nothing ever ran it.
func ApplyRLS(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, rlsSchema); err != nil {
		return fmt.Errorf("apply RLS policies: %w", err)
	}
	return nil
}
