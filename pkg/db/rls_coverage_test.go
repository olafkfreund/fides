package db

import (
	"context"
	"database/sql"
	"os"
	"sort"
	"strings"
	"testing"
)

// Every table carrying org_id must also carry a tenant_isolation policy, or the
// RLS backstop does not cover it.
//
// schema-rls.sql names its tables by hand, and migrations keep adding tables
// that nobody adds to that list. When this check was written, ten org-scoped
// tables had no policy -- all of them introduced after the list was authored.
// Nothing noticed, because nothing was looking. That is the failure this test
// exists to stop: not the ten, which are listed below and are being drained,
// but the eleventh.
//
// This is deliberately shaped like pkg/api's openapi_drift_test.go, which had
// the same problem (a hand-maintained list falling behind the code) and the same
// answer: read the truth from the database, gate on it, and carry a named
// backlog that only shrinks.
//
// Handler-level scoping is the primary control and covers these tables already
// -- TestEveryHandlerEstablishesTenantScope enforces it. So a table on this list
// is a missing backstop, not an open door. It still matters: the release notes
// say tenant isolation is on by default, and that claim should not be broader
// than the enforcement.
//
// uncoveredOrgTables only shrinks. A new org_id table belongs in schema-rls.sql,
// not here.
var uncoveredOrgTables = []string{
	"artifact_vulnerabilities",
	"control_exceptions",
	"integration_events",
	"sbom_components",
	"service_accounts",
	"service_owners",
	"sessions",
	"trail_anchors",
	"training_records",
	"vex_statements",
}

// orgScopedTablesWithoutPolicy asks the database which tables have an org_id
// column and no row-level security policy. Read from pg_catalog rather than
// parsed out of schema-rls.sql: the file says what we meant to apply, and the
// catalog says what is actually there.
func orgScopedTablesWithoutPolicy(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND a.attnum > 0
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_policies p
		    WHERE p.schemaname = 'public' AND p.tablename = c.relname
		  )
		ORDER BY 1`)
	if err != nil {
		t.Fatalf("query org-scoped tables: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return out
}

// Named ...Integration so CI actually runs it: the rls-integration job selects
// with -run 'Integration|EndToEnd' (go-build.yml), and the unsuffixed name
// matched nothing. A gate that never runs is worse than no gate -- it reads as
// protection while checking nothing, which is the exact shape of bug this file
// exists to catch.
func TestEveryOrgScopedTableHasAnRLSPolicyIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run RLS coverage integration tests")
	}
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// Both are idempotent and additive, so this is safe against the shared test
	// database sibling tests also use. Do not drop anything here.
	ctx := context.Background()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := ApplyRLS(ctx, conn); err != nil {
		// A role that cannot apply the policies cannot answer the question this
		// test asks. Locally that is ordinary -- a developer may be pointed at a
		// restricted role -- so skip. In CI it is not: the job owns its Postgres
		// and connects as its superuser, so a failure here means the check has
		// silently stopped checking. Skipping there would turn this gate into a
		// green light that measures nothing, which is how the ServiceNow e2e ran
		// clean for weeks without running (#492).
		if os.Getenv("CI") != "" {
			t.Fatalf("cannot apply RLS policies, so coverage cannot be measured: %v", err)
		}
		t.Skipf("the test role cannot apply RLS policies, so coverage cannot be measured: %v", err)
	}

	uncovered := orgScopedTablesWithoutPolicy(t, conn)

	known := map[string]bool{}
	for _, tbl := range uncoveredOrgTables {
		known[tbl] = true
	}

	var fresh []string
	for _, tbl := range uncovered {
		if !known[tbl] {
			fresh = append(fresh, tbl)
		}
	}
	sort.Strings(fresh)
	if len(fresh) > 0 {
		t.Errorf("%d table(s) carry org_id but have no RLS policy:\n  %s\n\n"+
			"Add them to the table list in schema-rls.sql (and its two byte-identical\n"+
			"copies). Do NOT add them to uncoveredOrgTables — that list is the backlog\n"+
			"from when this check was introduced and only shrinks.",
			len(fresh), strings.Join(fresh, "\n  "))
	}

	// The backlog must not rot either: an entry that is now covered, or whose
	// table no longer exists, has to leave the list. Otherwise it decays into
	// the same stale hand-maintained list this test exists to replace.
	stillUncovered := map[string]bool{}
	for _, tbl := range uncovered {
		stillUncovered[tbl] = true
	}
	var stale []string
	for _, tbl := range uncoveredOrgTables {
		if !stillUncovered[tbl] {
			stale = append(stale, tbl)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("uncoveredOrgTables has %d stale entry/entries — remove them, the gap is closed:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}

	var covered int
	if err := conn.QueryRow(`
		SELECT count(DISTINCT c.relname)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND a.attnum > 0
		WHERE n.nspname = 'public' AND c.relkind = 'r'`).Scan(&covered); err == nil {
		t.Logf("RLS coverage: %d of %d org-scoped tables have a policy, %d in the known backlog",
			covered-len(uncovered), covered, len(uncoveredOrgTables))
	}
}
