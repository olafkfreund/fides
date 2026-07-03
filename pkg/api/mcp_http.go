package api

import (
	"encoding/json"
	"net/http"

	"fides/pkg/mcp"
)

// handleMCPServer exposes Fides as a Model Context Protocol server over the
// Streamable HTTP transport, so REMOTE MCP clients (ServiceNow Now Assist,
// Claude, Cursor, ...) can call Fides tools over HTTP — the mirror of the stdio
// `fides-mcp`. It is authenticated by the tenant bearer token (the route is
// under authMiddleware) and scoped to the caller's org.
//
// POST /api/v1/mcp  — JSON-RPC 2.0: initialize | notifications/initialized |
// tools/list | tools/call. Responses are application/json (the client's Accept
// may also allow text/event-stream; JSON satisfies both).
func (s *Server) handleMCPServer(w http.ResponseWriter, r *http.Request) {
	var req mcp.JsonRpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	switch req.Method {
	case "initialize":
		s.rpcResult(w, req.Id, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fides", "version": "0.2.0"},
		})
	case "notifications/initialized", "notifications/cancelled":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.rpcResult(w, req.Id, map[string]any{"tools": fidesMCPTools()})
	case "tools/call":
		s.mcpToolsCall(w, r, req)
	default:
		s.rpcError(w, req.Id, -32601, "method not found: "+req.Method)
	}
}

// fidesMCPTools is the curated, read-only tool set exposed to remote MCP clients.
func fidesMCPTools() []mcp.Tool {
	return []mcp.Tool{
		{
			Name:        "ground_change",
			Description: "Ground Now Assist for a ServiceNow change: return Fides's authoritative control-coverage + evidence + change-gate risk for a change number, with a natural-language grounding_summary to quote verbatim. Fides advises; ServiceNow decides.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"change_number":{"type":"string","description":"ServiceNow change number, e.g. CHG0030192"}},"required":["change_number"]}`),
		},
		{
			Name:        "get_controls_coverage",
			Description: "List the org's governance controls and how many environments enforce each (coverage report across all frameworks).",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
	}
}

func (s *Server) mcpToolsCall(w http.ResponseWriter, r *http.Request, req mcp.JsonRpcRequest) {
	orgID, ok := principalOrg(r)
	if !ok {
		s.rpcError(w, req.Id, -32000, "unauthorized")
		return
	}
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	raw, _ := json.Marshal(req.Params)
	_ = json.Unmarshal(raw, &p)

	switch p.Name {
	case "ground_change":
		change, _ := p.Arguments["change_number"].(string)
		if change == "" {
			s.mcpToolError(w, req.Id, "change_number is required")
			return
		}
		pack, _, err := s.groundChange(r.Context(), orgID, change)
		if err != nil {
			s.mcpToolError(w, req.Id, err.Error())
			return
		}
		s.mcpToolJSON(w, req.Id, pack)
	case "get_controls_coverage":
		_, cov, err := s.controlsCoverageData(r.Context(), orgID)
		if err != nil {
			s.mcpToolError(w, req.Id, err.Error())
			return
		}
		s.mcpToolJSON(w, req.Id, map[string]any{"controls": cov})
	default:
		s.mcpToolError(w, req.Id, "unknown tool: "+p.Name)
	}
}

// --- JSON-RPC helpers ---

func (s *Server) rpcResult(w http.ResponseWriter, id any, result any) {
	raw, _ := json.Marshal(result)
	rm := json.RawMessage(raw)
	writeJSON(w, mcp.JsonRpcResponse{JsonRpc: "2.0", Id: id, Result: &rm})
}

func (s *Server) rpcError(w http.ResponseWriter, id any, code int, msg string) {
	writeJSON(w, mcp.JsonRpcResponse{JsonRpc: "2.0", Id: id, Error: &mcp.JsonRpcError{Code: code, Message: msg}})
}

// mcpToolJSON returns a successful tools/call result whose single text content is
// the JSON-encoded value (how MCP tools convey structured data).
func (s *Server) mcpToolJSON(w http.ResponseWriter, id any, v any) {
	body, _ := json.Marshal(v)
	s.rpcResult(w, id, mcp.ToolCallResult{Content: []mcp.TextContent{{Type: "text", Text: string(body)}}})
}

func (s *Server) mcpToolError(w http.ResponseWriter, id any, msg string) {
	s.rpcResult(w, id, mcp.ToolCallResult{IsError: true, Content: []mcp.TextContent{{Type: "text", Text: msg}}})
}
