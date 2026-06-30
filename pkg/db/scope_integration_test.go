package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// These tests require a real Postgres. They are skipped unless FIDES_TEST_DB_DSN
// is set, e.g.:
//
//	docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=fides \
//	  -p 55432:5432 postgres:15-alpine
//	FIDES_TEST_DB_DSN='host=127.0.0.1 port=55432 user=postgres password=test dbname=fides sslmode=disable' \
//	  go test ./pkg/db/ -run Integration -v
//
// The DSN user must be able to apply schema and SET ROLE (e.g. a superuser).
func testDSN(t *testing.T) string {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run RLS integration tests")
	}
	return dsn
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// setupRLS applies the schema + RLS, ensures a non-superuser role exists, and
// seeds two tenants with one flow each. It returns the two org IDs and a cleanup.
func setupRLS(t *testing.T, pool *sql.DB) (orgA, orgB uuid.UUID, cleanup func()) {
	ctx := context.Background()
	exec := func(sqlText string) {
		if _, err := pool.ExecContext(ctx, sqlText); err != nil {
			t.Fatalf("exec failed: %v\nSQL: %.120s", err, sqlText)
		}
	}

	exec(readRepoFile(t, "schema.sql"))
	exec(readRepoFile(t, "schema-rls.sql"))
	exec(`DO $$ BEGIN
	        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_rls_app') THEN
	          CREATE ROLE fides_rls_app NOLOGIN;
	        END IF;
	      END $$;
	      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_rls_app;`)

	orgA, orgB = uuid.New(), uuid.New()
	if _, err := pool.ExecContext(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1, $2), ($3, $4)`,
		orgA, "OrgA-"+orgA.String()[:8], orgB, "OrgB-"+orgB.String()[:8]); err != nil {
		t.Fatalf("seed orgs: %v", err)
	}
	if _, err := pool.ExecContext(ctx,
		`INSERT INTO flows (org_id, name) VALUES ($1, $2), ($3, $4)`,
		orgA, "flow-a", orgB, "flow-b"); err != nil {
		t.Fatalf("seed flows: %v", err)
	}
	// Seed an indirect-org row (a trail under OrgA's flow) to exercise the
	// chained join-path RLS policy.
	if _, err := pool.ExecContext(ctx,
		`INSERT INTO trails (flow_id, name)
		 SELECT id, 'trail-a' FROM flows WHERE org_id = $1`, orgA); err != nil {
		t.Fatalf("seed trail: %v", err)
	}

	cleanup = func() {
		_, _ = pool.ExecContext(ctx, `DELETE FROM organizations WHERE id IN ($1, $2)`, orgA, orgB)
	}
	return orgA, orgB, cleanup
}

func TestScopedConnEnforcesTenantIsolationIntegration(t *testing.T) {
	pool, err := sql.Open("postgres", testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	orgA, orgB, cleanup := setupRLS(t, pool)
	defer cleanup()
	ctx := context.Background()

	// Scope to OrgA and drop superuser privileges so RLS is enforced.
	conn, release, err := ScopedConn(ctx, pool, orgA.String())
	if err != nil {
		t.Fatalf("ScopedConn: %v", err)
	}
	defer release()
	if _, err := conn.ExecContext(ctx, "SET ROLE fides_rls_app"); err != nil {
		t.Fatalf("set role: %v", err)
	}

	// Read isolation: OrgA must see only its own flow.
	rows, err := conn.QueryContext(ctx, "SELECT name FROM flows ORDER BY name")
	if err != nil {
		t.Fatalf("query flows: %v", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	rows.Close()
	if len(names) != 1 || names[0] != "flow-a" {
		t.Fatalf("RLS read isolation failed: expected [flow-a], got %v", names)
	}

	// WITH CHECK: OrgA must not be able to insert a flow for OrgB.
	_, err = conn.ExecContext(ctx, "INSERT INTO flows (org_id, name) VALUES ($1, $2)", orgB.String(), "evil")
	if err == nil {
		t.Fatalf("expected cross-tenant insert to be blocked by RLS WITH CHECK")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
		t.Fatalf("expected an RLS violation error, got: %v", err)
	}

	// Indirect-org isolation: OrgA sees its trail (chained via flows).
	var trailCount int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM trails").Scan(&trailCount); err != nil {
		t.Fatalf("count trails (OrgA): %v", err)
	}
	if trailCount != 1 {
		t.Fatalf("OrgA should see exactly its 1 trail, got %d", trailCount)
	}

	// OrgB (a fresh scoped conn) must see zero trails.
	connB, releaseB, err := ScopedConn(ctx, pool, orgB.String())
	if err != nil {
		t.Fatalf("ScopedConn B: %v", err)
	}
	defer releaseB()
	if _, err := connB.ExecContext(ctx, "SET ROLE fides_rls_app"); err != nil {
		t.Fatalf("set role B: %v", err)
	}
	var trailCountB int
	if err := connB.QueryRowContext(ctx, "SELECT count(*) FROM trails").Scan(&trailCountB); err != nil {
		t.Fatalf("count trails (OrgB): %v", err)
	}
	if trailCountB != 0 {
		t.Fatalf("OrgB must not see OrgA's trail via the chained policy, got %d", trailCountB)
	}
}
