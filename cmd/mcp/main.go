package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// httpClient enforces a request timeout so a hung Fides server cannot block the
// MCP process indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// MCP Protocol structures
type JsonRpcRequest struct {
	JsonRpc string           `json:"jsonrpc"`
	Id      interface{}      `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  *json.RawMessage `json:"params,omitempty"`
}

type JsonRpcResponse struct {
	JsonRpc string      `json:"jsonrpc"`
	Id      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type JsonRpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

type ServerCapabilities struct {
	Tools struct{} `json:"tools"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string                `json:"type"`
	Properties map[string]SchemaProp `json:"properties"`
	Required   []string              `json:"required,omitempty"`
}

type SchemaProp struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type ToolCallParams struct {
	Name      string           `json:"name"`
	Arguments *json.RawMessage `json:"arguments,omitempty"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func main() {
	// Redirect standard logging to stderr since stdout/stdin is used for JSON-RPC
	log.SetOutput(os.Stderr)
	log.Println("Starting Fides MCP Server...")

	serverURL := os.Getenv("FIDES_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8191"
	}
	serverURL = strings.TrimSuffix(serverURL, "/")

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stdin: %v", err)
			continue
		}

		var req JsonRpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("Failed to parse request JSON: %v", err)
			sendError(nil, -32700, "Parse error", nil)
			continue
		}

		handleRequest(&req, serverURL)
	}
}

func handleRequest(req *JsonRpcRequest, serverURL string) {
	switch req.Method {
	case "initialize":
		var res InitializeResult
		res.ProtocolVersion = "2024-11-05"
		res.ServerInfo.Name = "fides-mcp"
		res.ServerInfo.Version = "1.0.0"
		sendResponse(req.Id, res)

	case "notifications/initialized":
		// No-op for initialized notification

	case "tools/list":
		var list ToolsListResult
		list.Tools = []Tool{
			{
				Name:        "list_flows",
				Description: "List all active build and CI/CD streams/flows in Fides",
				InputSchema: InputSchema{Type: "object", Properties: map[string]SchemaProp{}},
			},
			{
				Name:        "list_environments",
				Description: "List runtime environments monitored by Fides, along with current snapshots and drifts",
				InputSchema: InputSchema{Type: "object", Properties: map[string]SchemaProp{}},
			},
			{
				Name:        "list_policies",
				Description: "List all release gate security and compliance rules configs",
				InputSchema: InputSchema{Type: "object", Properties: map[string]SchemaProp{}},
			},
			{
				Name:        "check_compliance",
				Description: "Verify and query compliance of a build or artifact SHA256 signature against policy rules",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"artifact_sha256": {
							Type:        "string",
							Description: "The SHA256 signature hash of the artifact to check",
						},
					},
					Required: []string{"artifact_sha256"},
				},
			},
			{
				Name:        "get_change_request_status",
				Description: "Get the status of a ServiceNow change request (state, approval, risk, on_hold) by change number",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"change_number": {Type: "string", Description: "ServiceNow change number, e.g. CHG0030192"},
					},
					Required: []string{"change_number"},
				},
			},
			{
				Name:        "create_compliance_incident",
				Description: "Open a ServiceNow incident (e.g. when a Fides compliance gate fails)",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"short_description": {Type: "string", Description: "Incident title"},
						"description":       {Type: "string", Description: "Incident details"},
					},
					Required: []string{"short_description"},
				},
			},
			{
				Name:        "search_cmdb_ci",
				Description: "Search the ServiceNow CMDB for configuration items (owner, class, dependencies) by name",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"name": {Type: "string", Description: "CI name or partial name to search for"},
					},
					Required: []string{"name"},
				},
			},
			{
				Name:        "create_flow",
				Description: "Create a new pipeline or project flow stream in Fides",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"name": {
							Type:        "string",
							Description: "Unique name of the flow",
						},
						"description": {
							Type:        "string",
							Description: "Detailed description of the flow's purpose",
						},
					},
					Required: []string{"name"},
				},
			},
			{
				Name:        "create_trail",
				Description: "Initialize a new execution trail instance for a flow (e.g. CI build, Git PR)",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"flow_id": {
							Type:        "string",
							Description: "UUID of the flow this trail belongs to",
						},
						"name": {
							Type:        "string",
							Description: "Trail name (e.g. Git commit hash, build number, run ID)",
						},
						"git_repository": {
							Type:        "string",
							Description: "URL of the Git repository",
						},
						"git_commit": {
							Type:        "string",
							Description: "40-character commit SHA",
						},
						"git_branch": {
							Type:        "string",
							Description: "Branch name",
						},
						"git_message": {
							Type:        "string",
							Description: "Git commit message",
						},
					},
					Required: []string{"flow_id", "name"},
				},
			},
			{
				Name:        "report_artifact",
				Description: "Record a newly built artifact fingerprint (SHA256) into a build trail",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"sha256": {
							Type:        "string",
							Description: "SHA256 signature hash of the artifact",
						},
						"name": {
							Type:        "string",
							Description: "Filename, docker image tag, or logical identifier of the artifact",
						},
						"type": {
							Type:        "string",
							Description: "Artifact format type (e.g. docker, binary, tarball)",
						},
						"trail_id": {
							Type:        "string",
							Description: "UUID of the trail this artifact was built in",
						},
					},
					Required: []string{"sha256", "name", "type"},
				},
			},
			{
				Name:        "report_attestation",
				Description: "Upload quality evidence, test results, or vulnerability scanning reports for a build trail",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]SchemaProp{
						"trail_id": {
							Type:        "string",
							Description: "UUID of the trail this attestation belongs to",
						},
						"artifact_sha256": {
							Type:        "string",
							Description: "Optional: SHA256 of the specific artifact this evidence attests to",
						},
						"name": {
							Type:        "string",
							Description: "Attestation instance name (e.g. 'snyk-scan', 'unit-tests')",
						},
						"type_name": {
							Type:        "string",
							Description: "Attestation type schema name (e.g. 'snyk-scan', 'junit')",
						},
						"payload": {
							Type:        "string",
							Description: "JSON payload string representing the attestation findings or metrics",
						},
						"is_compliant": {
							Type:        "string",
							Description: "Boolean string ('true' or 'false') indicating if this single step meets compliance",
						},
					},
					Required: []string{"trail_id", "name", "type_name", "payload"},
				},
			},
		}
		sendResponse(req.Id, list)

	case "tools/call":
		if req.Params == nil {
			sendError(req.Id, -32602, "Invalid params", nil)
			return
		}
		var callParams ToolCallParams
		if err := json.Unmarshal(*req.Params, &callParams); err != nil {
			sendError(req.Id, -32602, "Invalid params format", nil)
			return
		}
		handleToolCall(req.Id, callParams, serverURL)

	default:
		sendError(req.Id, -32601, "Method not found", nil)
	}
}

func handleToolCall(reqId interface{}, params ToolCallParams, serverURL string) {
	var args map[string]interface{}
	if params.Arguments != nil {
		json.Unmarshal(*params.Arguments, &args)
	}

	var result ToolCallResult

	switch params.Name {
	case "list_flows":
		url := fmt.Sprintf("%s/api/v1/flows", serverURL)
		body, err := makeGetRequest(url)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error fetching flows: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "list_environments":
		url := fmt.Sprintf("%s/api/v1/environments", serverURL)
		body, err := makeGetRequest(url)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error fetching environments: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "list_policies":
		url := fmt.Sprintf("%s/api/v1/policies", serverURL)
		body, err := makeGetRequest(url)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error fetching policies: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "check_compliance":
		sha, ok := args["artifact_sha256"].(string)
		if !ok || sha == "" {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: "Missing artifact_sha256 parameter"}}
			break
		}
		q := neturl.Values{}
		q.Set("artifact_sha256", sha)
		reqURL := fmt.Sprintf("%s/api/v1/compliance?%s", serverURL, q.Encode())
		body, err := makeGetRequest(reqURL)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error checking compliance: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "get_change_request_status":
		num, ok := args["change_number"].(string)
		if !ok || num == "" {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: "Missing change_number parameter"}}
			break
		}
		q := neturl.Values{}
		q.Set("change_number", num)
		body, err := makeGetRequest(fmt.Sprintf("%s/api/v1/servicenow/change-status?%s", serverURL, q.Encode()))
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error querying change request: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "create_compliance_incident":
		short, ok := args["short_description"].(string)
		if !ok || short == "" {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: "Missing short_description parameter"}}
			break
		}
		desc, _ := args["description"].(string)
		body, err := makePostRequest(fmt.Sprintf("%s/api/v1/servicenow/incident", serverURL),
			map[string]string{"short_description": short, "description": desc})
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error creating incident: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "search_cmdb_ci":
		name, ok := args["name"].(string)
		if !ok || name == "" {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: "Missing name parameter"}}
			break
		}
		q := neturl.Values{}
		q.Set("name", name)
		body, err := makeGetRequest(fmt.Sprintf("%s/api/v1/servicenow/cmdb?%s", serverURL, q.Encode()))
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error searching CMDB: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "create_flow":
		name, _ := args["name"].(string)
		desc, _ := args["description"].(string)
		url := fmt.Sprintf("%s/api/v1/flows", serverURL)
		payload := map[string]string{"name": name, "description": desc}
		body, err := makePostRequest(url, payload)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error creating flow: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "create_trail":
		url := fmt.Sprintf("%s/api/v1/trails", serverURL)
		body, err := makePostRequest(url, args)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error creating trail: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "report_artifact":
		url := fmt.Sprintf("%s/api/v1/artifacts", serverURL)
		body, err := makePostRequest(url, args)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error reporting artifact: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	case "report_attestation":
		// convert is_compliant to bool
		isCompStr, _ := args["is_compliant"].(string)
		isComp := true
		if strings.ToLower(isCompStr) == "false" {
			isComp = false
		}

		payload := map[string]interface{}{
			"trail_id":        args["trail_id"],
			"artifact_sha256": args["artifact_sha256"],
			"name":            args["name"],
			"type_name":       args["type_name"],
			"payload":         args["payload"],
			"is_compliant":    isComp,
		}

		url := fmt.Sprintf("%s/api/v1/attestations", serverURL)
		body, err := makePostRequest(url, payload)
		if err != nil {
			result.IsError = true
			result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Error reporting attestation: %v", err)}}
		} else {
			result.Content = []TextContent{{Type: "text", Text: string(body)}}
		}

	default:
		result.IsError = true
		result.Content = []TextContent{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", params.Name)}}
	}

	sendResponse(reqId, result)
}

// setAuthHeaders applies the API token and organization scope from the
// environment. Identity must never be hardcoded in the binary.
func setAuthHeaders(req *http.Request) {
	if token := os.Getenv("FIDES_API_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if orgID := os.Getenv("FIDES_ORG_ID"); orgID != "" {
		req.Header.Set("X-Org-Id", orgID)
	}
}

func makeGetRequest(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	setAuthHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func makePostRequest(url string, payload interface{}) ([]byte, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setAuthHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func sendResponse(id interface{}, result interface{}) {
	var res JsonRpcResponse
	res.JsonRpc = "2.0"
	res.Id = id
	res.Result = result
	writeMessage(res)
}

func sendError(id interface{}, code int, message string, data interface{}) {
	var res JsonRpcResponse
	res.JsonRpc = "2.0"
	res.Id = id
	res.Error = JsonRpcError{
		Code:    code,
		Message: message,
		Data:    data,
	}
	writeMessage(res)
}

func writeMessage(msg interface{}) {
	bytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal JSON-RPC message: %v", err)
		return
	}
	os.Stdout.Write(bytes)
	os.Stdout.Write([]byte{'\n'})
}
