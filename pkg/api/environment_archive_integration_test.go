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
	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// Archiving an environment must take it out of the coverage denominator and
// nothing else. The real failure this guards: the e2e suite creates one
// environment per run and deletes none, so coverage fell every week for
// reasons that had nothing to do with compliance -- DORA read 6/15 = 40% when
// the honest figure across live environments was 6/10.
//
// The second half matters as much as the first. Archiving must not behave like
// deleting: the row, its policies and its id all have to survive, or "archive"
// becomes a data-loss button someone clicks to make a number look better.
func TestArchivedEnvironmentLeavesCoverageDenominator(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the environment-archive integration test")
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

	org, live, junk := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s'),($3,$2,'fides-e2e-1-env','k8s')`, live, org, junk)
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types) VALUES ($1,'p',$2)`, live, pq.StringArray([]string{"junit"}))
	mustExec(t, pool, `INSERT INTO controls (org_id,key,name,required_types) VALUES ($1,'SOC2-CC7.1','Testing',$2)`, org, pq.StringArray([]string{"junit"}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	coverage := func() (int, float64) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/controls/coverage", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleControlsCoverage(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("coverage: %d %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			TotalEnvironments int `json:"total_environments"`
			Controls          []struct {
				Coverage float64 `json:"coverage"`
			} `json:"controls"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Controls) != 1 {
			t.Fatalf("expected 1 control, got %d", len(resp.Controls))
		}
		return resp.TotalEnvironments, resp.Controls[0].Coverage
	}

	if total, cov := coverage(); total != 2 || cov != 0.5 {
		t.Fatalf("before archiving: want 2 envs at 0.5 coverage, got %d at %v", total, cov)
	}

	// Archive the abandoned e2e environment.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+junk.String()+"/archive", nil).WithContext(ctx)
	req.SetPathValue("id", junk.String())
	rec := httptest.NewRecorder()
	s.handleArchiveEnvironment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("archive: %d %s", rec.Code, rec.Body.String())
	}

	if total, cov := coverage(); total != 1 || cov != 1 {
		t.Fatalf("after archiving: want 1 env at full coverage, got %d at %v", total, cov)
	}

	// Archiving is not deleting: the row and its id survive.
	var archived bool
	if err := pool.QueryRow(`SELECT archived FROM environments WHERE id=$1`, junk).Scan(&archived); err != nil {
		t.Fatalf("archived environment row is gone: %v", err)
	}
	if !archived {
		t.Fatal("row survived but archived flag is false")
	}

	// And it is reversible.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+junk.String()+"/unarchive", nil).WithContext(ctx)
	req.SetPathValue("id", junk.String())
	rec = httptest.NewRecorder()
	s.handleUnarchiveEnvironment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unarchive: %d %s", rec.Code, rec.Body.String())
	}
	if total, cov := coverage(); total != 2 || cov != 0.5 {
		t.Fatalf("after unarchiving: want the original 2 envs at 0.5, got %d at %v", total, cov)
	}
}

// A control's policies must survive its environment being archived, so
// unarchiving restores the previous state rather than a blank environment.
func TestArchivingKeepsEnvironmentPolicies(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the environment-archive integration test")
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

	org, env := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'retiring','k8s')`, env, org)
	mustExec(t, pool, `INSERT INTO environment_policies (environment_id,name,required_types) VALUES ($1,'control:SOC2-CC7.1',$2)`, env, pq.StringArray([]string{"junit"}))
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+env.String()+"/archive", nil).WithContext(ctx)
	req.SetPathValue("id", env.String())
	rec := httptest.NewRecorder()
	s.handleArchiveEnvironment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("archive: %d %s", rec.Code, rec.Body.String())
	}

	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM environment_policies WHERE environment_id=$1`, env).Scan(&n); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if n != 1 {
		t.Fatalf("archiving destroyed evidence: expected the policy to survive, found %d", n)
	}
}

// Re-registering an archived environment by name brings it back. Without this
// the demo has a trap: archive demo-production, run the demo again, get a 201
// and an id for an environment that is absent from coverage and from the list.
func TestRecreatingAnArchivedEnvironmentUnarchivesIt(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the environment-archive integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org, env := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type,archived) VALUES ($1,$2,'demo-production','k8s',TRUE)`, env, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	body := strings.NewReader(`{"name":"demo-production","type":"k8s","description":"Created by demo/demo.sh"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments", body).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleCreateEnvironment(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	var archived bool
	if err := pool.QueryRow(`SELECT archived FROM environments WHERE id=$1`, env).Scan(&archived); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if archived {
		t.Fatal("re-registering left the environment archived: the demo would get an id it cannot see")
	}
}
