package api

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/crypto"
)

func TestParseAPIKeyRoundTrip(t *testing.T) {
	full, prefix, secret, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p, s, ok := parseAPIKey(full)
	if !ok || p != prefix || s != secret {
		t.Fatalf("round-trip failed: %q -> %q/%q ok=%v", full, p, s, ok)
	}
	for _, bad := range []string{"", "nope", "fides_only", "fides__", "fides_p_", "Bearer x"} {
		if _, _, ok := parseAPIKey(bad); ok {
			t.Fatalf("malformed key %q must not parse", bad)
		}
	}
}

func TestServiceAccountAuthIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the service-account auth integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.New()
	saID := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO service_accounts (id,org_id,name,role) VALUES ($1,$2,'ci','Writer')`, saID, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	full, prefix, secret, _ := generateAPIKey()
	hash, _ := crypto.HashPassword(secret)
	keyID := uuid.New()
	mustExec(t, pool, `INSERT INTO service_account_keys (id,service_account_id,prefix,key_hash) VALUES ($1,$2,$3,$4)`, keyID, saID, prefix, hash)

	s := &Server{DB: pool}
	ctx := context.Background()

	// Valid key authenticates with the account's org + role.
	if p := s.authServiceAccountKey(ctx, full); p == nil || p.OrgID != org || p.Role != auth.RoleWriter || p.Kind != "service" {
		t.Fatalf("valid key should authenticate as the account, got %+v", p)
	}
	// Wrong secret, unknown prefix -> nil.
	if s.authServiceAccountKey(ctx, keyScheme+prefix+"_wrongsecret") != nil {
		t.Fatalf("wrong secret must not authenticate")
	}
	if s.authServiceAccountKey(ctx, keyScheme+"deadbeef_"+secret) != nil {
		t.Fatalf("unknown prefix must not authenticate")
	}
	// Revoked key -> nil.
	mustExec(t, pool, `UPDATE service_account_keys SET revoked_at=now() WHERE id=$1`, keyID)
	if s.authServiceAccountKey(ctx, full) != nil {
		t.Fatalf("revoked key must not authenticate")
	}
}
