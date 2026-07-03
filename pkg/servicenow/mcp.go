package servicenow

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"fides/pkg/mcp"
)

// This file makes Fides a *client* of ServiceNow's Model Context Protocol (MCP)
// server, so Fides can read CMDB CIs, change requests, and GRC controls through
// ServiceNow's own governance layer rather than the raw Table API. Positioning:
// "Fides advises, ServiceNow decides" — Fides consumes SN's governed tools and
// records; SN remains the system of record.
//
// ServiceNow exposes two relevant surfaces (both under the tenant instance):
//   1. The GA MCP endpoint (standard MCP protocol, Streamable HTTP, OAuth):
//        <instance>/sncapps/mcp-server/mcp/<server>
//      discovered from the sn_mcp_server_registry table.
//   2. A governed scripted-REST facade used for direct record lookups:
//        POST /api/sn_mcp_server/mcp_lookup_service/get_records
//
// See docs/servicenow-mcp.md for setup + configuration.

// MCPServer is one provisioned MCP server from sn_mcp_server_registry.
type MCPServer struct {
	SysID  string `json:"sys_id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Status string `json:"status"`
}

// Active reports whether the server is provisioned and enabled.
func (s MCPServer) Active() bool { return strings.EqualFold(s.Status, "active") }

// ListMCPServers returns the ServiceNow MCP servers provisioned on the instance,
// so Fides can discover the GA MCP endpoint(s) to connect to.
func (c *Client) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	var out struct {
		Result []MCPServer `json:"result"`
	}
	const path = "/api/now/table/sn_mcp_server_registry" +
		"?sysparm_fields=sys_id,name,url,status&sysparm_limit=200"
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// MCPLookupResult is the response of ServiceNow's governed record-lookup tool.
// The service returns the matched record identifiers and a count; it is a
// discovery primitive (which records match), not a full field projection.
type MCPLookupResult struct {
	Records      []map[string]any `json:"records"`
	Count        float64          `json:"count"`
	Table        string           `json:"table"`
	EncodedQuery string           `json:"encodedQuery"`
}

// LookupRecords calls ServiceNow's MCP governed record-lookup service to find
// records in a table (e.g. cmdb_ci, change_request, sn_compliance_control)
// matching an encoded query, through SN's MCP governance rather than the raw
// Table API.
func (c *Client) LookupRecords(ctx context.Context, table, query string, limit int) (*MCPLookupResult, error) {
	if table == "" {
		return nil, fmt.Errorf("servicenow: LookupRecords requires a table")
	}
	if limit <= 0 {
		limit = 10
	}
	body := map[string]any{"table": table, "query": query, "limit": limit}
	var out struct {
		Result MCPLookupResult `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/sn_mcp_server/mcp_lookup_service/get_records", body, &out); err != nil {
		return nil, err
	}
	return &out.Result, nil
}

// MCPSession opens an initialized MCP session against a ServiceNow GA MCP server
// (standard MCP protocol over Streamable HTTP). serverName is a registry name
// (e.g. "sn_mcp_server_default"); if the registry has a URL for it that URL is
// used, otherwise the conventional path is constructed. The session is
// authenticated with the tenant's configured ServiceNow auth (OAuth bearer for
// the GA endpoint; basic auth is accepted only by instances that allow it).
func (c *Client) MCPSession(ctx context.Context, serverName string) (*mcp.HTTPClient, error) {
	endpoint, err := c.mcpEndpoint(ctx, serverName)
	if err != nil {
		return nil, err
	}
	if err := c.validate(endpoint); err != nil {
		return nil, err
	}

	authOpt, err := c.mcpAuthOption(ctx)
	if err != nil {
		return nil, err
	}
	client := mcp.NewHTTPClient(endpoint, authOpt, mcp.WithHTTPClient(c.http))
	if err := client.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("servicenow: MCP initialize failed for %q: %w", serverName, err)
	}
	return client, nil
}

// mcpEndpoint resolves the GA MCP endpoint URL for a server name, preferring the
// URL recorded in the registry and falling back to the conventional path.
func (c *Client) mcpEndpoint(ctx context.Context, serverName string) (string, error) {
	if serverName == "" {
		serverName = "sn_mcp_server_default"
	}
	servers, err := c.ListMCPServers(ctx)
	if err == nil {
		for _, s := range servers {
			if s.Name == serverName && s.URL != "" {
				return s.URL, nil
			}
		}
	}
	// Fallback: registry names dot-separate scope but the URL slug uses '_'.
	slug := strings.ReplaceAll(serverName, ".", "_")
	return c.cfg.InstanceURL + "/sncapps/mcp-server/mcp/" + slug, nil
}

// mcpAuthOption builds the MCP transport auth from the tenant's SN credentials.
func (c *Client) mcpAuthOption(ctx context.Context) (mcp.HTTPOption, error) {
	switch c.cfg.AuthType {
	case AuthOAuth2:
		tok, err := c.bearer(ctx)
		if err != nil {
			return nil, err
		}
		return mcp.WithBearer(tok), nil
	case AuthBasic:
		return mcp.WithBasicAuth(c.cfg.ClientID, c.cfg.Secret), nil
	default:
		return nil, fmt.Errorf("servicenow: unsupported auth type %q", c.cfg.AuthType)
	}
}
