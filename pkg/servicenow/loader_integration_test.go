package servicenow

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/vault"
)

// Postgres-backed test for DBLoader config resolution. Skipped unless
// FIDES_TEST_DB_DSN is set (see pkg/db for the Docker setup).
func TestServiceNowConfigIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run ServiceNow loader integration tests")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	if err := pool.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	org := uuid.New()
	if _, err := pool.Exec(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "snow-"+org.String()[:8]); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(`DELETE FROM organizations WHERE id = $1`, org) })

	t.Setenv("SNOW_SECRET_IT", "shhh")
	if _, err := pool.Exec(
		`INSERT INTO tenant_servicenow_settings (org_id, instance_url, auth_type, client_id, secret_path, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		org, "https://acme.service-now.com", "basic", "svc-acct", "SNOW_SECRET_IT"); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	loader := NewDBLoader(pool, vault.NewEnvSecretsProvider())
	cfg, enabled, err := loader.ServiceNowConfig(context.Background(), org)
	if err != nil {
		t.Fatalf("ServiceNowConfig: %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled config")
	}
	if cfg.InstanceURL != "https://acme.service-now.com" || cfg.AuthType != AuthBasic || cfg.ClientID != "svc-acct" {
		t.Fatalf("config mismatch: %+v", cfg)
	}
	if cfg.Secret != "shhh" {
		t.Fatalf("secret not resolved from provider: %q", cfg.Secret)
	}

	// A different org with no config -> not enabled.
	if _, en, err := loader.ServiceNowConfig(context.Background(), uuid.New()); err != nil || en {
		t.Fatalf("unconfigured org should be disabled, got enabled=%v err=%v", en, err)
	}
}

// The GRC sink files a verdict against every control the attestation is
// evidence for, so the array containment in ControlsForAttestation is the
// whole mapping. Exercised against real Postgres because `= ANY(required_types)`
// on a TEXT[] is the kind of thing that works in a mock and not in the database.
func TestControlsForAttestationIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run ServiceNow loader integration tests")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	org := uuid.New()
	if _, err := pool.Exec(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "grc-"+org.String()[:8]); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(`DELETE FROM organizations WHERE id = $1`, org) })

	other := uuid.New()
	if _, err := pool.Exec(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, other, "grc-other-"+other.String()[:8]); err != nil {
		t.Fatalf("seed other org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(`DELETE FROM organizations WHERE id = $1`, other) })

	seed := []struct {
		org      uuid.UUID
		key      string
		types    string
		archived bool
	}{
		{org, "SOC2-CC7.1", `{snyk-scan,trivy-scan}`, false}, // matches
		{org, "ISO27001-A.12.6", `{snyk-scan}`, false},       // matches
		{org, "SOC2-CC8.1", `{unit-tests}`, false},           // wrong type
		{org, "DORA-ICT-5", `{snyk-scan}`, true},             // archived
		{other, "SOC2-CC7.1", `{snyk-scan}`, false},          // another tenant
	}
	for _, s := range seed {
		if _, err := pool.Exec(
			`INSERT INTO controls (org_id, key, name, framework, required_types, archived)
			 VALUES ($1, $2, $3, 'test', $4::text[], $5)`,
			s.org, s.key, "name for "+s.key, s.types, s.archived); err != nil {
			t.Fatalf("seed control %s: %v", s.key, err)
		}
	}

	got, err := NewDBLoader(pool, vault.NewEnvSecretsProvider()).
		ControlsForAttestation(context.Background(), org, "snyk-scan")
	if err != nil {
		t.Fatalf("ControlsForAttestation: %v", err)
	}

	keys := map[string]bool{}
	for _, c := range got {
		keys[c.Key] = true
		if c.Name != "name for "+c.Key {
			t.Errorf("name not loaded for %s: %q", c.Key, c.Name)
		}
	}
	if len(got) != 2 || !keys["SOC2-CC7.1"] || !keys["ISO27001-A.12.6"] {
		t.Fatalf("want exactly the two live controls requiring snyk-scan, got %v", keys)
	}

	// A tenant with no matching control must come back empty, not with the
	// other tenant's rows — org scoping here is the tenant boundary, not a
	// backstop, because RLS is off by default on this deployment.
	empty, err := NewDBLoader(pool, vault.NewEnvSecretsProvider()).
		ControlsForAttestation(context.Background(), org, "no-such-type")
	if err != nil {
		t.Fatalf("ControlsForAttestation (unmapped): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("unmapped attestation returned %d control(s)", len(empty))
	}
}
