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
	defer pool.Close()
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
