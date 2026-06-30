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

func TestEnvironmentAllowlistIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the allowlist integration test")
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

	org, env := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, env, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "admin@x", Role: auth.RoleAdmin, Kind: "session"})
	sha := "abc123def456"

	// check before approval -> not approved
	if approved := checkAllow(t, s, ctx, env, sha); approved {
		t.Fatalf("should not be approved before adding")
	}
	// add
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"artifact_sha256":"`+sha+`","reason":"signed off"}`)).WithContext(ctx)
	req.SetPathValue("id", env.String())
	s.handleAddAllowlist(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	// check after approval -> approved
	if approved := checkAllow(t, s, ctx, env, sha); !approved {
		t.Fatalf("should be approved after adding")
	}
	// remove
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/x", nil).WithContext(ctx)
	req.SetPathValue("id", env.String())
	req.SetPathValue("sha", sha)
	s.handleRemoveAllowlist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	if approved := checkAllow(t, s, ctx, env, sha); approved {
		t.Fatalf("should not be approved after removal")
	}
}

func checkAllow(t *testing.T, s *Server, ctx context.Context, env uuid.UUID, sha string) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x?sha="+sha, nil).WithContext(ctx)
	req.SetPathValue("id", env.String())
	s.handleListAllowlist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("check: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Approved bool `json:"approved"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Approved
}
