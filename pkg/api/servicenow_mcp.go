package api

import (
	"encoding/json"
	"net/http"

	"fides/pkg/servicenow"
)

// ServiceNow MCP client endpoints: Fides consumes ServiceNow's Model Context
// Protocol server to discover MCP servers, read records (CMDB CIs, change
// requests, GRC controls) through SN's governed lookup, and list/call the
// governed MCP tools. "Fides advises, ServiceNow decides." See #167 and
// docs/servicenow-mcp.md.

// snMCPClient loads the tenant's ServiceNow config and returns a client, or
// writes an error response and returns false.
func (s *Server) snMCPClient(w http.ResponseWriter, r *http.Request) (*servicenow.Client, bool) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	cfg, enabled, err := servicenow.NewDBLoader(s.DB, s.Secrets).ServiceNowConfig(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return nil, false
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured for this organization", http.StatusBadRequest)
		return nil, false
	}
	client, err := servicenow.New(cfg)
	if err != nil {
		http.Error(w, "invalid ServiceNow configuration: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return client, true
}

// handleSNMCPServers lists the MCP servers provisioned on the ServiceNow instance.
func (s *Server) handleSNMCPServers(w http.ResponseWriter, r *http.Request) {
	client, ok := s.snMCPClient(w, r)
	if !ok {
		return
	}
	servers, err := client.ListMCPServers(r.Context())
	if err != nil {
		http.Error(w, "ServiceNow MCP server discovery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"servers": servers})
}

// handleSNMCPLookup reads records from a ServiceNow table through the MCP
// governed lookup service.
func (s *Server) handleSNMCPLookup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table string `json:"table"`
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Table == "" {
		http.Error(w, "table is required", http.StatusBadRequest)
		return
	}
	client, ok := s.snMCPClient(w, r)
	if !ok {
		return
	}
	res, err := client.LookupRecords(r.Context(), req.Table, req.Query, req.Limit)
	if err != nil {
		http.Error(w, "ServiceNow MCP lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
}

// handleSNMCPTools lists the tools a ServiceNow MCP server exposes.
func (s *Server) handleSNMCPTools(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	client, ok := s.snMCPClient(w, r)
	if !ok {
		return
	}
	sess, err := client.MCPSession(r.Context(), req.Server)
	if err != nil {
		http.Error(w, "ServiceNow MCP session failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	tools, err := sess.ListTools(r.Context())
	if err != nil {
		http.Error(w, "ServiceNow MCP tools/list failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"tools": tools})
}

// handleSNMCPCall invokes a governed tool on a ServiceNow MCP server.
func (s *Server) handleSNMCPCall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server    string          `json:"server"`
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Tool == "" {
		http.Error(w, "tool is required", http.StatusBadRequest)
		return
	}
	client, ok := s.snMCPClient(w, r)
	if !ok {
		return
	}
	sess, err := client.MCPSession(r.Context(), req.Server)
	if err != nil {
		http.Error(w, "ServiceNow MCP session failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	var args any
	if len(req.Arguments) > 0 {
		if err := json.Unmarshal(req.Arguments, &args); err != nil {
			badRequest(w, err)
			return
		}
	}
	out, err := sess.CallTool(r.Context(), req.Tool, args)
	if err != nil {
		http.Error(w, "ServiceNow MCP tools/call failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"result": out})
}
