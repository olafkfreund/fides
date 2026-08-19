package db

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// The default is the whole point of the change: opt-in RLS meant a deployment
// that never set the variable had no database-level isolation at all.
func TestRLSIsOnUnlessExplicitlyDisabled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		set   bool
		value string
		want  bool
	}{
		{"unset", false, "", true},
		{"empty", true, "", true},
		{"false", true, "false", false},
		{"true", true, "true", true},
		// Anything that is not exactly "false" leaves the backstop in place.
		// Failing open on a typo is the wrong direction for a security default.
		{"a typo", true, "flase", true},
		{"no", true, "no", true},
		{"0", true, "0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Unsetenv("FIDES_RLS_ENABLED")
			if tc.set {
				t.Setenv("FIDES_RLS_ENABLED", tc.value)
			}
			if got := RLSEnabled(); got != tc.want {
				t.Errorf("RLSEnabled() = %v with %q (set=%v), want %v", got, tc.value, tc.set, tc.want)
			}
		})
	}
}

// "RLS is enabled" and "RLS does anything" are different claims. A superuser
// ignores every policy, FORCE included, and the stock postgres image makes
// POSTGRES_USER a superuser — so the obvious deployment applies the policies
// and isolates nothing.
//
// Each attribute is tested on a role that has it and not the other. The stock
// superuser carries both, so against it the two checks cover for each other and
// removing either one changes nothing observable — which is exactly what
// mutation testing reported before these fixtures existed.
func TestRLSEffectiveDetectsARoleThatBypassesPolicies(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { admin.Close() })

	var canCreateRoles bool
	if err := admin.QueryRow(`SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user`).
		Scan(&canCreateRoles); err != nil {
		t.Fatalf("reading the current role: %v", err)
	}
	if !canCreateRoles {
		t.Skip("the test role cannot create the fixtures this needs")
	}

	base, err := url.Parse(dsnToURL(t, dsn))
	if err != nil {
		t.Fatalf("parsing the dsn: %v", err)
	}

	for _, tc := range []struct {
		name    string
		role    string
		attrs   string
		wantOK  bool
		wantWhy string
	}{
		{"a superuser without BYPASSRLS", "rls_su", "SUPERUSER NOBYPASSRLS", false, "superuser"},
		{"BYPASSRLS without superuser", "rls_bypass", "NOSUPERUSER BYPASSRLS", false, "BYPASSRLS"},
		{"an ordinary role", "rls_plain", "NOSUPERUSER NOBYPASSRLS", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin.Exec(`DROP ROLE IF EXISTS ` + tc.role)
			if _, err := admin.Exec(`CREATE ROLE ` + tc.role + ` LOGIN PASSWORD 'p' ` + tc.attrs); err != nil {
				t.Fatalf("creating %s: %v", tc.role, err)
			}
			t.Cleanup(func() { admin.Exec(`DROP ROLE IF EXISTS ` + tc.role) })

			u := *base
			u.User = url.UserPassword(tc.role, "p")
			pool, err := sql.Open("postgres", u.String())
			if err != nil {
				t.Fatalf("open as %s: %v", tc.role, err)
			}
			defer pool.Close()

			ok, why, err := RLSEffective(context.Background(), pool)
			if err != nil {
				t.Fatalf("RLSEffective as %s: %v", tc.role, err)
			}
			if ok != tc.wantOK {
				t.Errorf("effective = %v for %s, want %v (reason: %q)", ok, tc.attrs, tc.wantOK, why)
			}
			if tc.wantWhy != "" && !strings.Contains(why, tc.wantWhy) {
				t.Errorf("reason = %q, want it to mention %q — an operator has to know which attribute to remove",
					why, tc.wantWhy)
			}
		})
	}
}

// dsnToURL accepts either a URL dsn or a keyword dsn and returns a URL one.
func dsnToURL(t *testing.T, dsn string) string {
	t.Helper()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return dsn
	}
	fields := map[string]string{}
	for _, kv := range strings.Fields(dsn) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			fields[k] = v
		}
	}
	host, port := fields["host"], fields["port"]
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "5432"
	}
	u := url.URL{
		Scheme:   "postgres",
		Host:     host + ":" + port,
		Path:     "/" + fields["dbname"],
		RawQuery: "sslmode=" + fields["sslmode"],
	}
	return u.String()
}
