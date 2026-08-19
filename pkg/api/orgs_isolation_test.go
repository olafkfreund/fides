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

// A Viewer in one organisation must not learn that another exists.
func TestListOrgsDoesNotLeakOtherTenants(t *testing.T) {
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

	mine, theirs := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, theirs, "ACME-SECRET-CUSTOMER-"+theirs.String()[:8])
	t.Cleanup(func() {
		pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, mine, theirs)
	})

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleViewer, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleListOrgs(rec, req)

	body := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, body)

	// Assert the status too: an error response decodes to zero orgs, which
	// would otherwise read as "isolated" and pass this test vacuously.
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, body)
	}
	var orgs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(body), &orgs); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	for _, o := range orgs {
		if o.ID == theirs.String() || strings.Contains(o.Name, "ACME-SECRET-CUSTOMER") {
			t.Fatalf("LEAK: a Viewer in org %s was shown org %s (%q)", mine, o.ID, o.Name)
		}
	}
}

// Creating an organisation must not be available to an ordinary tenant.
func TestCreateOrgIsNotOpenToAnyTenant(t *testing.T) {
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
	pool.Exec(string(schema))

	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs",
		strings.NewReader(`{"name":"squatted-by-a-viewer"}`))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleViewer, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleCreateOrg(rec, req)
	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	if rec.Code < 400 {
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(rec.Body.Bytes(), &created)
		if created.ID != "" {
			pool.Exec(`DELETE FROM organizations WHERE id=$1`, created.ID)
		}
		t.Fatalf("LEAK: a Viewer created an organisation (code=%d)", rec.Code)
	}
}

// The gate must not break the operation it guards: an Admin still creates.
// Without this, deleting the whole handler would pass the two tests above.
func TestAnAdminCanStillCreateAnOrg(t *testing.T) {
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
	pool.Exec(string(schema))

	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs",
		strings.NewReader(`{"name":"legitimate-new-tenant"}`))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleAdmin, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleCreateOrg(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("an Admin could not create an org: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID != "" {
		t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, created.ID) })
	}
}

// And the caller still sees its own organization — scoping must not empty it.
func TestListOrgsStillReturnsYourOwn(t *testing.T) {
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
	pool.Exec(string(schema))

	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: mine, Role: auth.RoleViewer, Kind: "service"}))
	rec := httptest.NewRecorder()
	srv.handleListOrgs(rec, req)

	var orgs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &orgs); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(orgs) != 1 || orgs[0].ID != mine.String() {
		t.Fatalf("caller should see exactly its own org, got %s", rec.Body.String())
	}
}
