package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// environment_mcp_servers rows hold an auth_header and env_vars — credentials
// the in-cluster sensor uses. environment_id arrives from the caller, so these
// probe whether it is checked against the caller's org.
func mcpProbeDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return pool
}

// twoTenants returns (mine, theirsEnvID); theirs has an MCP server holding a secret.
func twoTenants(t *testing.T, pool *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	mine, theirs := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, theirs, "theirs-"+theirs.String()[:8])
	theirEnv := uuid.New()
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,$3,'k8s')`,
		theirEnv, theirs, "prod")
	t.Cleanup(func() {
		pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, mine, theirs)
	})
	return mine, theirEnv
}

func TestListEnvMCPServersDoesNotLeakAnotherTenantsCredentials(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)
	mustExec(t, pool, `INSERT INTO environment_mcp_servers (environment_id,name,transport,url,auth_header,env_vars)
	                   VALUES ($1,'sensor','sse','https://theirs.internal','Bearer SUPER-SECRET-TOKEN','{"API_KEY":"SECRET-ENV"}'::jsonb)`, theirEnv)

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/environments/mcp?environment_id="+theirEnv.String(), nil)
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleListEnvironmentMCPServers(rec, req)

	body := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, body)
	if strings.Contains(body, "SUPER-SECRET-TOKEN") || strings.Contains(body, "SECRET-ENV") {
		t.Fatalf("LEAK: another tenant's MCP credentials were returned: %s", body)
	}
}

func TestSaveEnvMCPServerCannotTargetAnotherTenantsEnvironment(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)

	srv := NewServer(pool, nil, nil)
	body := `{"environment_id":"` + theirEnv.String() + `","name":"pwned","transport":"sse","url":"https://attacker.example"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/mcp", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleSaveEnvironmentMCPServer(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM environment_mcp_servers WHERE environment_id=$1 AND name='pwned'`,
		theirEnv).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: wrote an MCP server into another tenant's environment (status %d)", rec.Code)
	}
}

// The legitimate path must keep working.
func TestEnvMCPServersStillWorkWithinYourOwnOrg(t *testing.T) {
	pool := mcpProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	myEnv := uuid.New()
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, myEnv, mine)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	ctx := auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"})

	body := `{"environment_id":"` + myEnv.String() + `","name":"sensor","transport":"sse","url":"https://mine.internal"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/mcp", strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	srv.handleSaveEnvironmentMCPServer(rec, req)
	if rec.Code >= 400 {
		t.Fatalf("own-org save should succeed, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/environments/mcp?environment_id="+myEnv.String(), nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	srv.handleListEnvironmentMCPServers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("own-org list should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(list) != 1 {
		t.Fatalf("want own server listed, got %s", rec.Body.String())
	}
}

// handleReportSnapshot guards the environment with RLS rather than in-query.
// RLS is opt-in (FIDES_RLS_ENABLED), and these tests run without it — the same
// configuration a default deployment has.
func TestReportSnapshotCannotTargetAnotherTenantsEnvironment(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)

	srv := NewServer(pool, nil, nil)
	body := `{"environment_id":"` + theirEnv.String() + `","artifacts":[{"sha256":"` +
		strings.Repeat("ab", 32) + `","service_name":"planted"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/snapshot", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleReportSnapshot(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM environment_snapshots WHERE environment_id=$1`,
		theirEnv).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: wrote a snapshot into another tenant's environment (status %d)", rec.Code)
	}
}

// handleQueryEnvironmentMCPServer executes the stored command, so an unguarded
// environment_id means running another tenant's configured process. The refusal
// must come before any of that.
func TestQueryEnvMCPServerRefusesAnotherTenantsEnvironment(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)
	mustExec(t, pool, `INSERT INTO environment_mcp_servers (environment_id,name,transport,command)
	                   VALUES ($1,'sensor','stdio','/bin/should-never-run')`, theirEnv)

	srv := NewServer(pool, nil, nil)
	body := `{"environment_id":"` + theirEnv.String() + `","server_name":"sensor","tool_name":"whatever"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/mcp/query", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleQueryEnvironmentMCPServer(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's environment, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyEnvComplianceRefusesAnotherTenantsEnvironment(t *testing.T) {
	pool := mcpProbeDB(t)
	mine, theirEnv := twoTenants(t, pool)
	mustExec(t, pool, `INSERT INTO environment_mcp_servers (environment_id,name,transport,command)
	                   VALUES ($1,'sensor','stdio','/bin/should-never-run')`, theirEnv)

	srv := NewServer(pool, nil, nil)
	body := `{"environment_id":"` + theirEnv.String() + `","server_name":"sensor","tool_name":"whatever","rules":[".ok"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/verify", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleVerifyEnvironmentCompliance(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for another tenant's environment, got %d: %s", rec.Code, rec.Body.String())
	}
}
