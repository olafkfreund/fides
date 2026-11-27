package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A minimal Streamable-HTTP MCP server: it answers initialize (issuing a
// session id), tools/list, and tools/call, and echoes the session id it expects
// on follow-up calls.
func mockMCPServer(t *testing.T, sse bool) *httptest.Server {
	t.Helper()
	const sessionID = "sess-123"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want Bearer tok", got)
		}
		body, _ := io.ReadAll(r.Body)
		var req JsonRpcRequest
		json.Unmarshal(body, &req)

		// Notifications carry no id and expect no body.
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", sessionID)
			result = map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]string{"name": "mock"}}
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != sessionID {
				t.Errorf("tools/list missing session id header, got %q", r.Header.Get("Mcp-Session-Id"))
			}
			result = map[string]any{"tools": []map[string]any{
				{"name": "lookup_records", "description": "governed table lookup"},
			}}
		case "tools/call":
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": "CHG0030277"}}}
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
			return
		}

		resp, _ := json.Marshal(JsonRpcResponse{JsonRpc: "2.0", Id: req.Id, Result: rawJSON(result)})
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message\ndata: " + string(resp) + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
}

func rawJSON(v any) *json.RawMessage {
	b, _ := json.Marshal(v)
	rm := json.RawMessage(b)
	return &rm
}

func TestHTTPClientHandshakeAndTools(t *testing.T) {
	for _, sse := range []bool{false, true} {
		srv := mockMCPServer(t, sse)
		c := NewHTTPClient(srv.URL, WithBearer("tok"), WithHTTPClient(srv.Client()))
		if err := c.Initialize(context.Background()); err != nil {
			t.Fatalf("sse=%v Initialize: %v", sse, err)
		}
		if c.sessionID != "sess-123" {
			t.Fatalf("sse=%v session id not captured: %q", sse, c.sessionID)
		}
		tools, err := c.ListTools(context.Background())
		if err != nil {
			t.Fatalf("sse=%v ListTools: %v", sse, err)
		}
		if len(tools) != 1 || tools[0].Name != "lookup_records" {
			t.Fatalf("sse=%v unexpected tools: %+v", sse, tools)
		}
		out, err := c.CallTool(context.Background(), "lookup_records", map[string]any{"table": "change_request"})
		if err != nil {
			t.Fatalf("sse=%v CallTool: %v", sse, err)
		}
		if out != "CHG0030277" {
			t.Fatalf("sse=%v CallTool result = %q", sse, out)
		}
		srv.Close()
	}
}

func TestLastSSEData(t *testing.T) {
	raw := []byte("event: message\ndata: {\"a\":1}\n\nevent: message\ndata: {\"b\":2}\n\n")
	got := lastSSEData(raw)
	if string(got) != `{"b":2}` {
		t.Fatalf("lastSSEData = %q, want the last data frame", string(got))
	}
	if lastSSEData([]byte("event: ping\n\n")) != nil {
		t.Fatalf("expected nil when there is no data frame")
	}
}

func TestHTTPClientReportsErrorFromConfiguredEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/mcp" {
			t.Errorf("request = %s %s, want POST /mcp", r.Method, r.URL.Path)
		}
		if user, pass, ok := r.BasicAuth(); !ok || user != "test-user" || pass != "test-pass" {
			t.Error("request missing configured basic auth")
		}
		http.Error(w, "test endpoint rejected the request", http.StatusForbidden)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL+"/mcp", WithBasicAuth("test-user", "test-pass"))
	_, err := client.ListTools(t.Context())
	if err == nil || err.Error() != "mcp: http 403: test endpoint rejected the request" {
		t.Fatalf("ListTools error = %v, want HTTP 403 with response message", err)
	}
}
