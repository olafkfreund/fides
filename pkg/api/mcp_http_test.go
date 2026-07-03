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

	"fides/pkg/auth"
	"fides/pkg/mcp"
)

func mcpPost(t *testing.T, s *Server, ctx context.Context, body string) mcp.JsonRpcResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader([]byte(body))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleMCPServer(rec, req)
	var resp mcp.JsonRpcResponse
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return resp
}

// initialize + tools/list need no database.
func TestMCPServerInitializeAndList(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	init := mcpPost(t, s, ctx, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if init.Error != nil || init.Result == nil {
		t.Fatalf("initialize failed: %+v", init)
	}
	var info struct {
		ServerInfo struct{ Name string } `json:"serverInfo"`
	}
	json.Unmarshal(*init.Result, &info)
	if info.ServerInfo.Name != "fides" {
		t.Errorf("serverInfo.name = %q, want fides", info.ServerInfo.Name)
	}

	list := mcpPost(t, s, ctx, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	var tl struct {
		Tools []mcp.Tool `json:"tools"`
	}
	json.Unmarshal(*list.Result, &tl)
	names := map[string]bool{}
	for _, x := range tl.Tools {
		names[x.Name] = true
	}
	if !names["ground_change"] || !names["get_controls_coverage"] {
		t.Fatalf("tools/list missing expected tools: %+v", tl.Tools)
	}
}

// tools/call ground_change over the HTTP MCP transport returns the grounding pack.
func TestMCPServerGroundChange(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the MCP ground_change test")
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
	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	control, att := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	mustExec(t, pool, `INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'SOC2-CC8.1','Tests',ARRAY['junit'])`, control, org)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant) VALUES ($1,$2,'ut','junit','{}',true)`, att, trail)
	mustExec(t, pool,
		`INSERT INTO change_control_links (org_id,trail_id,control_id,attestation_id,change_number,linked_by) VALUES ($1,$2,$3,$4,'CHG0030192','ci@x')`,
		org, trail, control, att)

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	resp := mcpPost(t, s, ctx, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ground_change","arguments":{"change_number":"CHG0030192"}}}`)
	if resp.Error != nil || resp.Result == nil {
		t.Fatalf("tools/call failed: %+v", resp)
	}
	var tc mcp.ToolCallResult
	json.Unmarshal(*resp.Result, &tc)
	if tc.IsError || len(tc.Content) == 0 {
		t.Fatalf("tool returned error/empty: %+v", tc)
	}
	var pack struct {
		Grounded bool `json:"grounded"`
	}
	json.Unmarshal([]byte(tc.Content[0].Text), &pack)
	if !pack.Grounded {
		t.Errorf("expected grounded:true in the tool result, got: %s", tc.Content[0].Text)
	}
}
