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

// Regression: the AI-assistant "list flows" / "find failing trails" commands in
// handleAIChat ran unscoped SELECTs (s.q with no org_id), so with RLS disabled
// (the default) they returned every tenant's flows. This asserts org A's
// "list flows" shows only org A's flow, never org B's.
func TestAIChatListFlowsScopedByOrg(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the AI-chat org-scope integration test")
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

	orgA, orgB := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgA, "a-"+orgA.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgB, "b-"+orgB.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'alpha-flow','')`, uuid.New(), orgA)
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'bravo-flow','')`, uuid.New(), orgB)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: orgA, Role: auth.RoleAdmin, Kind: "session"})

	body, _ := json.Marshal(aiChatReq{Message: "list flows"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/chat", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleAIChat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ai chat: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var resp aiChatResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(resp.Response, "alpha-flow") {
		t.Fatalf("own org's flow missing from response: %q", resp.Response)
	}
	if strings.Contains(resp.Response, "bravo-flow") {
		t.Fatalf("cross-tenant leak: org B's flow visible to org A: %q", resp.Response)
	}
}
