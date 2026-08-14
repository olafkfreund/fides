package db

import (
	"os"
	"strings"
	"testing"
)

// The embedded copy must stay byte-identical to the repo-root schema-rls.sql,
// exactly as migrations/0001_init.sql mirrors schema.sql.
//
// The copy exists only because go:embed cannot reach outside its package
// directory. If the two drift, the server silently applies a different policy
// set from the one reviewers read at the repo root -- and a policy set nobody
// looked at is how service_accounts ended up under tenant_isolation, breaking
// every API key on RLS deployments (#429).
func TestEmbeddedRLSSchemaMatchesRoot(t *testing.T) {
	root, err := os.ReadFile("../../schema-rls.sql")
	if err != nil {
		t.Fatalf("read schema-rls.sql: %v", err)
	}
	if string(root) != rlsSchema {
		t.Fatal("schema-rls.sql and pkg/db/schema-rls.sql have diverged — " +
			"copy the root file over the embedded one so the server applies what reviewers read")
	}
}

// The whole point of applying it on every boot is that it can be re-run. A
// policy file that is not idempotent would fail the second start.
func TestEmbeddedRLSSchemaSelfHealsServiceAccounts(t *testing.T) {
	for _, want := range []string{
		"ALTER TABLE service_account_keys DISABLE ROW LEVEL SECURITY",
		"ALTER TABLE service_accounts DISABLE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS tenant_isolation ON service_accounts",
	} {
		if !strings.Contains(rlsSchema, want) {
			t.Errorf("embedded RLS schema no longer contains %q; API-key auth breaks on RLS deployments without it", want)
		}
	}
}
