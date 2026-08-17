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
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

func TestCreateEnvironment(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the create-environment integration test")
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
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	create := func(body string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/environments", bytes.NewReader([]byte(body))).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleCreateEnvironment(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create env: HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	first := create(`{"name":"prod-k8s","type":"k8s","description":"cluster"}`)
	if first["id"] == "" || first["type"] != "k8s" {
		t.Fatalf("unexpected create response: %+v", first)
	}
	// Idempotent upsert by (org, name): same name returns the same id.
	second := create(`{"name":"prod-k8s","type":"k8s","description":"updated"}`)
	if second["id"] != first["id"] {
		t.Fatalf("upsert changed id: %v -> %v", first["id"], second["id"])
	}

	// Missing name/type -> 400.
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/environments", bytes.NewReader([]byte(`{"type":"k8s"}`))).WithContext(ctx)
	badRec := httptest.NewRecorder()
	s.handleCreateEnvironment(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d", badRec.Code)
	}

	// Appears in the list (as a non-null array).
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil).WithContext(ctx)
	lrec := httptest.NewRecorder()
	s.handleListEnvironments(lrec, lreq)
	if !strings.Contains(lrec.Body.String(), "prod-k8s") {
		t.Fatalf("created env missing from list: %s", lrec.Body.String())
	}
}
