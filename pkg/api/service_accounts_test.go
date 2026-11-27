package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/db"
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
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
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

func TestReadOnlyServiceAccountKeyIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	const scopeError = "route is outside the read-only key scope"
	keyRoute := "/api/v1/tenant/service-accounts/" + f.own["account"] + "/keys"
	admin := f.sessions[auth.RoleAdmin]

	f.denied(t, "POST "+keyRoute, `{"read_only":true}`, admin, http.StatusBadRequest, "read-only keys require a Viewer service account")
	mustExec(t, f.pool, `UPDATE service_accounts SET role=$1, may_delegate_approvals=true WHERE id=$2`, auth.RoleViewer, f.own["account"])
	f.denied(t, "POST "+keyRoute, `{"read_only":"true"}`, admin, http.StatusBadRequest, "invalid request")

	issue := func(body string, wantScope bool) (routeCredential, string) {
		t.Helper()
		rec := serveMutation(t, f.handler, "POST "+keyRoute, body, admin, http.StatusCreated, "")
		var key struct {
			Token    string `json:"api_key"`
			Prefix   string `json:"prefix"`
			ReadOnly *bool  `json:"read_only"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &key); err != nil || key.Token == "" ||
			key.ReadOnly == nil || *key.ReadOnly != wantScope {
			t.Fatalf("issuance response missing key or expected scope: %v", err)
		}
		var id string
		if err := f.pool.QueryRow(`SELECT id FROM service_account_keys WHERE prefix=$1`, key.Prefix).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return routeBearer(key.Token), id
	}
	scoped, scopedID := issue(`{"read_only":true,"label":"mcp","expires_hours":1}`, true)
	legacy, legacyID := issue("", false)

	mustExec(t, f.pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type)
		VALUES ($1,$2,$3,'scoped artifact','container')`, f.own["sha"], f.own["org"], f.own["trail"])
	mustExec(t, f.pool, `UPDATE flows SET name='other tenant flow' WHERE id=$1`, f.other["flow"])
	before := f.snapshot(t)
	for _, path := range []string{
		"/api/v1/flows",
		"/api/v1/environments",
		"/api/v1/policies",
		"/api/v1/compliance?sha256=" + f.own["sha"],
		"/api/v1/search/artifacts",
		"/api/v1/search/attestations",
		"/api/v1/controls/coverage",
		"/api/v1/metrics/deployment-frequency",
	} {
		rec := serveMutation(t, f.handler, "GET "+path, "", scoped, http.StatusOK, "")
		if path == "/api/v1/flows" && (!strings.Contains(rec.Body.String(), f.own["flow"]) || strings.Contains(rec.Body.String(), f.other["flow"])) {
			t.Fatal("scoped flow listing did not stay within the key's tenant")
		}
	}
	serveMutation(t, f.handler, "GET /api/v1/servicenow/grounding?change=CHG0000001", "", scoped, http.StatusNotFound, "")

	for _, rpc := range []struct{ body, want string }{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "ground_change"},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_controls_coverage"}}`, "Seed control"},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ground_change","arguments":{"change_number":"CHG0000001"}}}`, "CHG0000001"},
	} {
		rec := serveMutation(t, f.handler, "POST /api/v1/mcp", rpc.body, scoped, http.StatusOK, "")
		if strings.Contains(rec.Body.String(), `"isError":true`) || !strings.Contains(rec.Body.String(), rpc.want) {
			t.Errorf("scoped HTTP MCP did not return %q: %s", rpc.want, rec.Body)
		}
	}
	serveMutation(t, f.handler, "POST /api/v1/flows", `{"name":"fixture"}`, scoped, http.StatusForbidden, scopeError)
	serveMutation(t, f.handler, "GET /api/v1/trails/"+f.own["trail"]+"/change-gate", "", scoped, http.StatusForbidden, scopeError)
	serveMutation(t, f.handler, "GET /api/v1/servicenow/change-status?change_number=CHG0000001", "", scoped, http.StatusForbidden, scopeError)
	serveMutation(t, f.handler, "GET /api/v1/servicenow/cmdb?name=fixture", "", scoped, http.StatusForbidden, scopeError)
	serveMutation(t, f.handler, "GET "+keyRoute, "", scoped, http.StatusForbidden, scopeError)
	if changed := changedRouteTables(before, f.snapshot(t)); len(changed) != 0 {
		t.Fatalf("scoped requests wrote to %v", changed)
	}

	rec := serveMutation(t, f.handler, "GET "+keyRoute, "", legacy, http.StatusOK, "")
	if !strings.Contains(rec.Body.String(), `"read_only":true`) {
		t.Error("key listing did not include the stored scope")
	}
	var used bool
	if err := f.pool.QueryRow(`SELECT last_used_at IS NOT NULL FROM service_account_keys WHERE id=$1`, legacyID).Scan(&used); err != nil || !used {
		t.Fatalf("legacy key usage stamp missing: %v", err)
	}
	serveMutation(t, f.handler, "DELETE "+keyRoute+"/"+scopedID, "", admin, http.StatusOK, "")
	f.denied(t, "GET /api/v1/flows", "", scoped, http.StatusUnauthorized, "invalid credentials")
	serveMutation(t, f.handler, "GET /api/v1/flows", "", legacy, http.StatusOK, "")
}
