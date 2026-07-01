package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// The embedded 0001_init.sql must stay byte-identical to the canonical root
// schema.sql, so fresh installs and migrations never diverge.
func TestEmbeddedSchemaMatchesRoot(t *testing.T) {
	root, err := os.ReadFile("../../schema.sql")
	if err != nil {
		t.Fatalf("read root schema: %v", err)
	}
	embedded, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read embedded 0001: %v", err)
	}
	if string(root) != string(embedded) {
		t.Fatalf("schema.sql and pkg/db/migrations/0001_init.sql have diverged — " +
			"copy schema.sql to pkg/db/migrations/0001_init.sql (and add a new NNNN_*.sql for column changes)")
	}
}

// The Helm chart bundles copies of schema.sql and schema-rls.sql (its seed Job
// is self-contained). They must match the repo-root canonical files.
func TestHelmChartSQLMatchesRoot(t *testing.T) {
	for _, f := range []string{"schema.sql", "schema-rls.sql"} {
		root, err := os.ReadFile("../../" + f)
		if err != nil {
			t.Fatalf("read root %s: %v", f, err)
		}
		chart, err := os.ReadFile("../../charts/fides/files/" + f)
		if err != nil {
			t.Fatalf("read chart %s: %v", f, err)
		}
		if string(root) != string(chart) {
			t.Fatalf("charts/fides/files/%s has diverged from root %s — copy the root file into the chart", f, f)
		}
	}
}

// Postgres-backed: Migrate creates the schema, is idempotent, and records
// versions. Skipped unless FIDES_TEST_DB_DSN is set.
func TestMigrateIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run migration integration tests")
	}
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// Migrate is idempotent and additive, so it is safe to run against whatever
	// state the shared test database is in (do NOT drop the schema here — sibling
	// integration tests share this database).
	ctx := context.Background()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	// A second run must be a clean no-op.
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("second Migrate (idempotent): %v", err)
	}

	// Tables and the additive columns must exist.
	checks := map[string]string{
		"users.password_hash":                 "SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='password_hash'",
		"tenant_git_providers.inbound_secret": "SELECT 1 FROM information_schema.columns WHERE table_name='tenant_git_providers' AND column_name='inbound_secret_path'",
		"tenant_servicenow_settings":          "SELECT 1 FROM information_schema.tables WHERE table_name='tenant_servicenow_settings'",
	}
	for name, q := range checks {
		var ok int
		if err := conn.QueryRow(q).Scan(&ok); err != nil {
			t.Fatalf("expected %s to exist after migrate: %v", name, err)
		}
	}

	// Both migrations recorded.
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("expected >=2 recorded migrations, got %d (err=%v)", n, err)
	}
}
