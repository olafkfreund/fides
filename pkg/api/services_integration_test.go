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

func TestServiceRegistry(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the service-registry test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	pool.Exec(string(schema))
	mig, _ := os.ReadFile(filepath.Join("..", "..", "pkg", "db", "migrations", "0024_service_registry.sql"))
	if _, err := pool.Exec(string(mig)); err != nil {
		t.Fatalf("migration 0024: %v", err)
	}
	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	save := func(body string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/services", bytes.NewReader([]byte(body))).WithContext(ctx)
		rec := httptest.NewRecorder()
		s.handleSaveService(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("save: HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	// tier clamps to 3.
	if m := save(`{"service":"api","owner":"a@x","tier":5}`); m["tier"].(float64) != 3 {
		t.Fatalf("tier not clamped: %v", m["tier"])
	}
	// upsert same service changes the tier.
	if m := save(`{"service":"api","owner":"a@x","tier":2}`); m["tier"].(float64) != 2 {
		t.Fatalf("upsert tier = %v, want 2", m["tier"])
	}
	// list shows it once.
	lrec := httptest.NewRecorder()
	s.handleListServices(lrec, httptest.NewRequest(http.MethodGet, "/api/v1/services", nil).WithContext(ctx))
	if strings.Count(lrec.Body.String(), `"api"`) != 1 {
		t.Fatalf("expected 'api' once, got: %s", lrec.Body.String())
	}
}
