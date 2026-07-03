package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPClient is a minimal Model Context Protocol client over the Streamable HTTP
// transport (a single endpoint that accepts JSON-RPC POSTs and may reply with
// either application/json or a text/event-stream of SSE frames). It performs the
// initialize -> notifications/initialized handshake, carrying the server-issued
// Mcp-Session-Id header on subsequent requests.
//
// This complements the stdio transport in client.go: remote MCP servers (e.g.
// ServiceNow's GA MCP server at /sncapps/mcp-server/mcp/<server>) are reached
// over HTTP, not by launching a local process.
type HTTPClient struct {
	endpoint  string
	http      *http.Client
	header    http.Header
	sessionID string
	nextID    int
}

// HTTPOption configures an HTTPClient.
type HTTPOption func(*HTTPClient)

// WithBearer authenticates requests with an OAuth bearer token.
func WithBearer(token string) HTTPOption {
	return func(c *HTTPClient) { c.header.Set("Authorization", "Bearer "+token) }
}

// WithBasicAuth authenticates requests with HTTP basic auth.
func WithBasicAuth(user, pass string) HTTPOption {
	return func(c *HTTPClient) {
		req := &http.Request{Header: http.Header{}}
		req.SetBasicAuth(user, pass)
		c.header.Set("Authorization", req.Header.Get("Authorization"))
	}
}

// WithHeader sets an arbitrary request header (e.g. a custom auth or tenant id).
func WithHeader(key, value string) HTTPOption {
	return func(c *HTTPClient) { c.header.Set(key, value) }
}

// WithHTTPClient overrides the underlying *http.Client (for tests / custom TLS).
func WithHTTPClient(hc *http.Client) HTTPOption {
	return func(c *HTTPClient) { c.http = hc }
}

// NewHTTPClient builds a Streamable HTTP MCP client for the given endpoint URL.
func NewHTTPClient(endpoint string, opts ...HTTPOption) *HTTPClient {
	c := &HTTPClient{
		endpoint: endpoint,
		http:     &http.Client{Timeout: 30 * time.Second},
		header:   http.Header{},
		nextID:   1,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Tool is one entry from a tools/list response.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Initialize performs the MCP handshake and records the session id, if any.
func (c *HTTPClient) Initialize(ctx context.Context) error {
	params := InitializeParams{
		ProtocolVersion: "2025-06-18",
		Capabilities:    struct{}{},
		ClientInfo:      ClientInfo{Name: "fides", Version: "1.0.0"},
	}
	var result json.RawMessage
	if err := c.call(ctx, "initialize", params, &result); err != nil {
		return err
	}
	// Best-effort: tell the server we're ready. Notifications carry no id and
	// expect no response body.
	_ = c.notify(ctx, "notifications/initialized")
	return nil
}

// ListTools returns the tools the MCP server exposes.
func (c *HTTPClient) ListTools(ctx context.Context) ([]Tool, error) {
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := c.call(ctx, "tools/list", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

// CallTool invokes a tool and returns the concatenated text content.
func (c *HTTPClient) CallTool(ctx context.Context, name string, arguments any) (string, error) {
	var out ToolCallResult
	if err := c.call(ctx, "tools/call", CallToolParams{Name: name, Arguments: arguments}, &out); err != nil {
		return "", err
	}
	if out.IsError {
		return "", fmt.Errorf("mcp: tool %q returned an error: %s", name, firstText(out.Content))
	}
	return firstText(out.Content), nil
}

func firstText(content []TextContent) string {
	parts := make([]string, 0, len(content))
	for _, t := range content {
		if t.Text != "" {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// call sends a JSON-RPC request expecting a response, decoding result into out.
func (c *HTTPClient) call(ctx context.Context, method string, params any, out any) error {
	id := c.nextID
	c.nextID++
	reqBody, _ := json.Marshal(JsonRpcRequest{JsonRpc: "2.0", Id: id, Method: method, Params: params})

	resp, err := c.post(ctx, reqBody)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("mcp: %s returned error %d: %s", method, resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return fmt.Errorf("mcp: empty response for %s", method)
	}
	if out != nil {
		if err := json.Unmarshal(*resp.Result, out); err != nil {
			return fmt.Errorf("mcp: decode %s result: %w", method, err)
		}
	}
	return nil
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (c *HTTPClient) notify(ctx context.Context, method string) error {
	body, _ := json.Marshal(JsonRpcRequest{JsonRpc: "2.0", Method: method})
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return nil
}

// post sends one JSON-RPC request and parses a single JSON-RPC response,
// transparently handling both application/json and text/event-stream replies.
func (c *HTTPClient) post(ctx context.Context, body []byte) (*JsonRpcResponse, error) {
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// A server may (re)issue the session id on any response.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mcp: http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	payload := raw
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		payload = lastSSEData(raw)
		if payload == nil {
			return nil, fmt.Errorf("mcp: no data frame in event stream")
		}
	}
	var jr JsonRpcResponse
	if err := json.Unmarshal(payload, &jr); err != nil {
		return nil, fmt.Errorf("mcp: decode response: %w", err)
	}
	return &jr, nil
}

func (c *HTTPClient) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range c.header {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	// The Streamable HTTP transport lets the server choose JSON or SSE.
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	return req, nil
}

// lastSSEData returns the JSON payload of the last non-empty `data:` line in an
// SSE body — MCP puts each JSON-RPC message in one SSE `data:` field.
func lastSSEData(raw []byte) []byte {
	var last []byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data:") {
			d := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if d != "" && d != "[DONE]" {
				last = []byte(d)
			}
		}
	}
	return last
}
