package servicenow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListMCPServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/now/table/sn_mcp_server_registry") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`{"result":[
			{"sys_id":"1","name":"sn_mcp_server.default","url":"https://x/sncapps/mcp-server/mcp/sn_mcp_server_default","status":"active"},
			{"sys_id":"2","name":"calitii_demo","url":"","status":""}
		]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	servers, err := c.ListMCPServers(context.Background())
	if err != nil {
		t.Fatalf("ListMCPServers: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("want 2 servers, got %d", len(servers))
	}
	if !servers[0].Active() || servers[1].Active() {
		t.Fatalf("Active() wrong: %+v", servers)
	}
}

func TestLookupRecords(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sn_mcp_server/mcp_lookup_service/get_records" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"result":{"records":[{"number":"CHG0030277"},{"number":"CHG0031000"}],"count":2,"table":"change_request","encodedQuery":"active=true"}}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	res, err := c.LookupRecords(context.Background(), "change_request", "active=true", 5)
	if err != nil {
		t.Fatalf("LookupRecords: %v", err)
	}
	if res.Count != 2 || len(res.Records) != 2 || res.Table != "change_request" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if gotBody["table"] != "change_request" || gotBody["query"] != "active=true" || gotBody["limit"].(float64) != 5 {
		t.Fatalf("request body not sent correctly: %+v", gotBody)
	}
}

// MCPSession resolves the endpoint from the registry and completes the MCP
// initialize handshake against the GA endpoint.
func TestMCPSession(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/api/now/table/sn_mcp_server_registry", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[{"sys_id":"1","name":"sn_mcp_server_default","url":"` +
			srv.URL + `/sncapps/mcp-server/mcp/sn_mcp_server_default","status":"active"}]}`))
	})
	mux.HandleFunc("/sncapps/mcp-server/mcp/sn_mcp_server_default", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("MCP request missing Authorization header")
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		json.Unmarshal(body, &req)
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Session-Id", "s1")
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"protocolVersion": "2025-06-18"}})
		w.Write(resp)
	})

	c := testClient(srv.URL, AuthBasic, srv.Client())
	sess, err := c.MCPSession(context.Background(), "sn_mcp_server_default")
	if err != nil {
		t.Fatalf("MCPSession: %v", err)
	}
	if sess == nil {
		t.Fatal("expected a session")
	}
}
