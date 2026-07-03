package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// A duplicate trail name for the same flow (UNIQUE(flow_id, name)) must return
// 409 Conflict, not 500 (#262). Gated by FIDES_TEST_DB_DSN.
func TestCreateTrailDuplicateNameReturns409(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the create-trail integration test")
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

	org, flow := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)

	s := &Server{DB: pool}
	create := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(createTrailReq{FlowID: flow.String(), Name: "dup-trail"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/trails", bytes.NewReader(body)).WithContext(context.Background())
		rec := httptest.NewRecorder()
		s.handleCreateTrail(rec, req)
		return rec
	}

	if rec := create(); rec.Code != http.StatusCreated {
		t.Fatalf("first create: HTTP %d (want 201): %s", rec.Code, rec.Body.String())
	}
	if rec := create(); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: HTTP %d (want 409): %s", rec.Code, rec.Body.String())
	}
}
