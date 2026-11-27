package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/db"
)

// Exercise both role gates and the assistant's narrower write gate. The full
// route and credential matrix lives in the #523 regression suite.
func TestDocumentedMutationRolesIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run mutation role integration")
	}
	t.Setenv("FIDES_RLS_ENABLED", "false")
	t.Setenv("FIDES_EVENTS_ENABLED", "false")
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	org, flow := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, org.String())
	t.Cleanup(func() { mustExec(t, pool, `DELETE FROM organizations WHERE id = $1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id, org_id, name) VALUES ($1,$2,'seed-flow')`, flow, org)
	srv := &Server{DB: pool, Sessions: auth.NewSessionStore()}
	handler := srv.Routes()
	tokens := make(map[string]string)
	for _, role := range []string{auth.RoleAdmin, auth.RoleWriter, auth.RoleViewer, auth.RoleAuditor} {
		token, err := srv.Sessions.Create(auth.Principal{OrgID: org, Role: role, Kind: "session"}, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		tokens[role] = token
	}
	request := func(role, path, body string, status int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tokens[role]})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s as %s: HTTP %d, want %d, response %s", path, role, rec.Code, status, rec.Body)
		}
	}

	for _, role := range []string{auth.RoleViewer, auth.RoleAuditor, auth.RoleWriter} {
		request(role, "/api/v1/flows", `{"name":"denied-flow"}`, http.StatusForbidden)
		request(role, "/api/v1/ai/chat", `{"message":"create flow denied-assistant-flow"}`, http.StatusForbidden)
		request(role, "/api/v1/ai/chat", `{"message":"list flows"}`, http.StatusOK)
	}
	trail := func(name string) string { return fmt.Sprintf(`{"flow_id":%q,"name":%q}`, flow, name) }
	for _, role := range []string{auth.RoleViewer, auth.RoleAuditor} {
		request(role, "/api/v1/trails", trail("denied-trail"), http.StatusForbidden)
	}
	request(auth.RoleAdmin, "/api/v1/flows", `{"name":"admin-flow"}`, http.StatusCreated)
	request(auth.RoleAdmin, "/api/v1/ai/chat", `{"message":"create flow assistant-flow description fixture"}`, http.StatusOK)
	request(auth.RoleWriter, "/api/v1/trails", trail("writer-trail"), http.StatusCreated)
	request(auth.RoleAdmin, "/api/v1/trails", trail("admin-trail"), http.StatusCreated)

	var flows, trails int
	if err := pool.QueryRow(`SELECT (SELECT count(*) FROM flows WHERE org_id = $1),
		(SELECT count(*) FROM trails WHERE flow_id = $2)`, org, flow).Scan(&flows, &trails); err != nil {
		t.Fatal(err)
	}
	if flows != 3 || trails != 2 {
		t.Fatalf("got %d flows and %d trails, want 3 and 2", flows, trails)
	}
}
