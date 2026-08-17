package api

import (
	"context"
	"database/sql"
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

// Regression: list endpoints must serialize an empty result as `[]`, not `null`.
// A `var list []T` that is never appended marshals to JSON null, which crashed
// the portal (e.g. flows.filter(...) on null) for any org with no rows — every
// fresh tenant hit it. This asserts the contract for the reported pages.
func TestListEndpointsEmptyReturnArray(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the empty-list-array integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "empty-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	cases := []struct {
		path string
		h    func(http.ResponseWriter, *http.Request)
	}{
		{"/api/v1/flows", s.handleListFlows},
		{"/api/v1/environments", s.handleListEnvironments},
		{"/api/v1/policies", s.handleListPolicies},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		c.h(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: HTTP %d: %s", c.path, rec.Code, rec.Body.String())
			continue
		}
		body := strings.TrimSpace(rec.Body.String())
		if body == "null" || !strings.HasPrefix(body, "[") {
			t.Errorf("%s returned %q on empty org — want a JSON array []", c.path, body)
		}
	}
}
