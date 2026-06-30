package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fides/pkg/auth"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// E2E proof that with FIDES_RLS_ENABLED the full HTTP -> middleware ->
// scoped-conn -> handler chain isolates tenants via Postgres RLS while the
// server connects as a non-superuser role. Skipped unless FIDES_TEST_DB_DSN is
// set (a superuser DSN used for setup).
func TestRLSEndToEndTenantIsolation(t *testing.T) {
	superDSN := os.Getenv("FIDES_TEST_DB_DSN")
	if superDSN == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the RLS E2E test")
	}

	readRepo := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}

	// --- Setup as superuser: schema, RLS, least-privilege app role, seed.
	super, err := sql.Open("postgres", superDSN)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	defer super.Close()
	if err := super.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	mustExec := func(q string, args ...any) {
		if _, err := super.Exec(q, args...); err != nil {
			t.Fatalf("exec failed: %v\nSQL: %.100s", err, q)
		}
	}
	mustExec(readRepo("schema.sql"))
	mustExec(readRepo("schema-rls.sql"))
	mustExec(`DO $$ BEGIN
	            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_e2e_app') THEN
	              CREATE ROLE fides_e2e_app LOGIN PASSWORD 'app';
	            END IF;
	          END $$;
	          GRANT USAGE ON SCHEMA public TO fides_e2e_app;
	          GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_e2e_app;
	          GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_e2e_app;`)

	orgA, orgB := uuid.New(), uuid.New()
	mustExec(`INSERT INTO organizations (id, name) VALUES ($1,$2),($3,$4)`,
		orgA, "A-"+orgA.String()[:8], orgB, "B-"+orgB.String()[:8])
	mustExec(`INSERT INTO flows (org_id, name, description) VALUES ($1,'flow-a','a'),($2,'flow-b','b')`, orgA, orgB)
	t.Cleanup(func() { _, _ = super.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB) })

	// --- The server's pool connects as the non-superuser app role so RLS applies.
	appDSN := withUserPassword(superDSN, "fides_e2e_app", "app")
	appPool, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()
	if err := appPool.Ping(); err != nil {
		t.Fatalf("app ping: %v", err)
	}

	t.Setenv("FIDES_RLS_ENABLED", "true")
	t.Setenv("FIDES_API_TOKEN", "unused-but-required")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	srv := NewServer(appPool, nil, nil)
	tokenA, _ := srv.Sessions.Create(auth.Principal{OrgID: orgA, Role: auth.RoleViewer, Kind: "session"}, time.Hour, time.Now())
	tokenB, _ := srv.Sessions.Create(auth.Principal{OrgID: orgB, Role: auth.RoleViewer, Kind: "session"}, time.Hour, time.Now())

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	listFlowNames := func(sessionToken string) []string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/flows", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var flows []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&flows); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var names []string
		for _, f := range flows {
			names = append(names, f.Name)
		}
		return names
	}

	if got := listFlowNames(tokenA); len(got) != 1 || got[0] != "flow-a" {
		t.Fatalf("OrgA should see only flow-a via RLS, got %v", got)
	}
	if got := listFlowNames(tokenB); len(got) != 1 || got[0] != "flow-b" {
		t.Fatalf("OrgB should see only flow-b via RLS, got %v", got)
	}
}

// withUserPassword rewrites a space-separated key=value libpq DSN, overriding
// the user and password fields.
func withUserPassword(dsn, user, password string) string {
	fields := map[string]string{}
	var order []string
	for _, kv := range strings.Fields(dsn) {
		if i := strings.IndexByte(kv, '='); i > 0 {
			k := kv[:i]
			if _, seen := fields[k]; !seen {
				order = append(order, k)
			}
			fields[k] = kv[i+1:]
		}
	}
	fields["user"] = user
	fields["password"] = password
	for _, k := range []string{"user", "password"} {
		found := false
		for _, o := range order {
			if o == k {
				found = true
			}
		}
		if !found {
			order = append(order, k)
		}
	}
	var b strings.Builder
	for i, k := range order {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k + "=" + fields[k])
	}
	return b.String()
}
