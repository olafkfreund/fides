package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
)

// RLSEnabled reports whether tenant isolation should be enforced in the
// database as well as in the handlers.
//
// **On unless explicitly disabled**, which is the opposite of how this started.
// It was opt-in, and opt-in meant that in a default deployment s.q() handed
// back the unscoped pool and a handler that forgot to filter on the principal's
// org had no isolation at all. Four separate cross-tenant defects were found
// that way in one day (#456, #457, #458, #460). The handlers are all scoped
// now, and the point of a backstop is to be there for the fifth one nobody
// found.
//
// FIDES_RLS_ENABLED=false still turns it off, so a deployment that needs to
// roll back has a way that does not involve a code change.
func RLSEnabled() bool {
	return os.Getenv("FIDES_RLS_ENABLED") != "false"
}

// RLSEffective reports whether the RLS policies can actually constrain this
// connection, and why not when they cannot.
//
// The check exists because "RLS is enabled" and "RLS does anything" are
// different claims, and only the second one is worth making. A PostgreSQL
// superuser — or any role with BYPASSRLS — ignores every policy, FORCE ROW
// LEVEL SECURITY included. The stock postgres image creates POSTGRES_USER as a
// superuser, and docker-compose connects as exactly that role, so the obvious
// deployment would apply the policies, set app.current_org on every request,
// log "RLS policies applied", and isolate nothing.
//
// Announcing isolation that is not being enforced is worse than not claiming it
// at all: it is the sort of thing that ends up in a compliance questionnaire.
func RLSEffective(ctx context.Context, db *sql.DB) (bool, string, error) {
	var user string
	var super, bypass bool
	err := db.QueryRowContext(ctx,
		`SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&user, &super, &bypass)
	if err != nil {
		return false, "", fmt.Errorf("checking whether RLS applies to this connection: %w", err)
	}
	switch {
	case super:
		return false, fmt.Sprintf("the database user %q is a superuser, and superusers ignore every "+
			"row-level security policy", user), nil
	case bypass:
		return false, fmt.Sprintf("the database user %q holds BYPASSRLS", user), nil
	}
	return true, "", nil
}

// RequireRLSEffective turns a backstop that is not working into a refusal to
// start.
//
// RLSEffective only reports; this decides. It was a warning first, and a
// warning is the wrong shape for this: the deployment it fires on is precisely
// the one that believes it has database-level tenant isolation and does not,
// and a WARNING line at boot is read by nobody three weeks later. "RLS policies
// applied" in the log above it actively encourages the wrong conclusion.
//
// Refusing is safe to adopt because it only fires when RLS is switched ON. A
// deployment that has deliberately turned it off (docker-compose does, because
// it connects as POSTGRES_USER) never reaches this check. So the boot failures
// this can cause are all deployments claiming isolation they do not have —
// which is the case worth interrupting.
//
// Both ways out are in the message, because an operator hitting this at 3am
// needs the fix, not the diagnosis.
func RequireRLSEffective(ctx context.Context, db *sql.DB) error {
	ok, why, err := RLSEffective(ctx, db)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return fmt.Errorf(
		"refusing to start: tenant isolation is switched on but the database is not enforcing it — %s.\n"+
			"  Handlers still scope every query to the caller's organization, so this is a missing\n"+
			"  backstop rather than an open door. It is fatal because the alternative is logging\n"+
			"  \"RLS policies applied\" next to a database that ignores them.\n"+
			"  Fix it in one of two ways:\n"+
			"    1. Connect as a role that RLS can constrain — not a superuser, no BYPASSRLS.\n"+
			"       The recipe is at the top of pkg/db/schema-rls.sql (CREATE ROLE fides_app ...).\n"+
			"    2. Set FIDES_RLS_ENABLED=false to run without the database backstop, relying on\n"+
			"       handler-level scoping alone. This is a real option, not a workaround — but it\n"+
			"       should be a decision someone typed, which is the point of making it explicit.",
		why)
}
