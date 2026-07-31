package api

import (
	"bytes"
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

func TestTrainingRecords(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the training-records test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	pool.Exec(string(schema))
	mig, _ := os.ReadFile(filepath.Join("..", "..", "pkg", "db", "migrations", "0025_training_records.sql"))
	if _, err := pool.Exec(string(mig)); err != nil {
		t.Fatalf("migration 0025: %v", err)
	}
	org := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/training", bytes.NewReader([]byte(`{"person":"olaf","course":"owasp-top-10"}`))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleRecordTraining(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	lrec := httptest.NewRecorder()
	s.handleListTraining(lrec, httptest.NewRequest(http.MethodGet, "/api/v1/training", nil).WithContext(ctx))
	if !strings.Contains(lrec.Body.String(), "owasp-top-10") {
		t.Fatalf("training record missing from list: %s", lrec.Body.String())
	}
}
