// Command mcp-sensor is a minimal but protocol-correct stdio MCP server for
// Fides environment compliance checks. Unlike `echo`, it completes the MCP
// JSON-RPC handshake (initialize -> initialized -> tools/call) the Fides client
// expects, so "Verify Compliance" works against a real MCP server.
//
// The tool response payload is taken from MCP_SENSOR_RESPONSE (so each
// environment connection can supply its own state JSON via env vars); it falls
// back to a small compliant workload snapshot.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

const defaultResponse = `{"pods":[{"name":"fides-app","status":"Ready","replicas":1,"readyReplicas":1}]}`

type rpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
}

type rpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

func main() {
	resp := os.Getenv("MCP_SENSOR_RESPONSE")
	if resp == "" {
		resp = defaultResponse
	}
	serve(os.Stdin, os.Stdout, resp)
}

// serve runs the MCP stdio loop, replying to initialize/tools/list/tools/call.
func serve(in io.Reader, out io.Writer, toolResponse string) {
	reader := bufio.NewReader(in)
	enc := json.NewEncoder(out)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			var req rpcRequest
			if json.Unmarshal(line, &req) == nil {
				if result, ok := handle(req, toolResponse); ok {
					_ = enc.Encode(rpcResponse{JsonRpc: "2.0", ID: req.ID, Result: result})
				}
			}
		}
		if err != nil {
			return // EOF or read error
		}
	}
}

// handle returns the result for a request, or ok=false for notifications
// (which take no id and get no response).
func handle(req rpcRequest, toolResponse string) (any, bool) {
	if len(req.ID) == 0 { // notification (e.g. notifications/initialized)
		return nil, false
	}
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fides-mcp-sensor", "version": "1.0.0"},
		}, true
	case "tools/list":
		return map[string]any{"tools": []map[string]any{
			{"name": "get_pods", "description": "Return the current workload/pod state snapshot as JSON"},
			{"name": "get_state", "description": "Return the current environment state snapshot as JSON"},
		}}, true
	case "tools/call":
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": toolResponse},
		}}, true
	default:
		return map[string]any{}, true
	}
}
