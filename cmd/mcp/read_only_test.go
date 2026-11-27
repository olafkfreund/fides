package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestMCPReadOnlyStdio(t *testing.T) {
	if os.Getenv("FIDES_MCP_READ_ONLY_TEST_PROCESS") == "1" {
		runMCP(flag.Args())
		os.Exit(0)
	}

	tools := []struct {
		name, request string
		readOnly      bool
		destructive   bool
	}{
		{"list_flows", "GET /api/v1/flows", true, false},
		{"list_environments", "GET /api/v1/environments", true, false},
		{"list_policies", "GET /api/v1/policies", true, false},
		{"check_compliance", "GET /api/v1/compliance", true, false},
		{"get_change_request_status", "GET /api/v1/servicenow/change-status", false, false},
		{"create_compliance_incident", "POST /api/v1/servicenow/incident", false, false},
		{"search_cmdb_ci", "GET /api/v1/servicenow/cmdb", false, false},
		{"search_artifacts", "GET /api/v1/search/artifacts", true, false},
		{"search_attestations", "GET /api/v1/search/attestations", true, false},
		{"get_controls_coverage", "GET /api/v1/controls/coverage", true, false},
		{"ground_change", "GET /api/v1/servicenow/grounding", true, false},
		{"get_deployment_frequency", "GET /api/v1/metrics/deployment-frequency", true, false},
		{"create_flow", "POST /api/v1/flows", false, false},
		{"create_trail", "POST /api/v1/trails", false, false},
		{"report_artifact", "POST /api/v1/artifacts", false, true},
		{"report_attestation", "POST /api/v1/attestations", false, false},
	}
	if len(toolRegistry) != len(tools) {
		t.Fatalf("classification fixtures cover %d of %d registered tools", len(tools), len(toolRegistry))
	}

	for _, tc := range []struct {
		name, env, flag, protocol string
		readOnly                  bool
	}{
		{name: "default"},
		{name: "environment", env: "true", readOnly: true},
		{name: "flag overrides false", env: "false", flag: "--read-only", readOnly: true},
		{name: "flag overrides true", env: "true", flag: "--read-only=false"},
		{name: "legacy protocol", protocol: "2024-11-05"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.Method+" "+r.URL.Path)
				mu.Unlock()
				_, _ = io.WriteString(w, "[]")
			}))
			defer server.Close()

			var input bytes.Buffer
			enc := json.NewEncoder(&input)
			send := func(id int, method string, params any) {
				t.Helper()
				if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
					t.Fatal(err)
				}
			}
			protocol := tc.protocol
			if protocol == "" {
				protocol = "2025-03-26"
			}
			send(1, "initialize", map[string]string{"protocolVersion": protocol})
			send(2, "tools/list", nil)
			args := map[string]string{
				"name": "fixture", "short_description": "fixture incident", "change_number": "CHG0001",
				"artifact_sha256": "sha256:fixture", "sha256": "sha256:fixture", "type": "fixture",
				"flow_id": "00000000-0000-4000-8000-000000000001", "trail_id": "00000000-0000-4000-8000-000000000002",
				"type_name": "fixture", "payload": "{}",
			}
			for i, tool := range tools {
				send(i+3, "tools/call", map[string]any{"name": tool.name, "arguments": args})
			}
			send(len(tools)+3, "tools/call", map[string]string{"name": "unknown"})

			processArgs := []string{"-test.run=^TestMCPReadOnlyStdio$", "--"}
			if tc.flag != "" {
				processArgs = append(processArgs, tc.flag)
			}
			cmd := exec.CommandContext(t.Context(), os.Args[0], processArgs...)
			cmd.Env = append(os.Environ(), "FIDES_MCP_READ_ONLY_TEST_PROCESS=1", "FIDES_MCP_READ_ONLY="+tc.env,
				"FIDES_SERVER_URL="+server.URL, "FIDES_API_TOKEN=", "FIDES_ORG_ID=")
			cmd.Stdin = &input
			cmd.Stderr = os.Stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(output))
			read := func(id int, result any) {
				t.Helper()
				response := struct {
					ID     int             `json:"id"`
					Result json.RawMessage `json:"result"`
					Error  json.RawMessage `json:"error"`
				}{}
				if err := decoder.Decode(&response); err != nil {
					t.Fatalf("read reply %d: %v", id, err)
				}
				if response.ID != id || len(response.Error) != 0 {
					t.Fatalf("reply %d: %+v", id, response)
				}
				if err := json.Unmarshal(response.Result, result); err != nil {
					t.Fatal(err)
				}
			}
			var init InitializeResult
			read(1, &init)
			if init.ProtocolVersion != protocol {
				t.Fatalf("negotiated protocol = %s, want %s", init.ProtocolVersion, protocol)
			}

			var list struct {
				Tools []struct {
					Name        string           `json:"name"`
					Annotations map[string]*bool `json:"annotations"`
				} `json:"tools"`
			}
			read(2, &list)
			discovered := make(map[string]map[string]*bool)
			for _, tool := range list.Tools {
				if _, duplicate := discovered[tool.Name]; duplicate {
					t.Errorf("duplicate tool %s", tool.Name)
				}
				discovered[tool.Name] = tool.Annotations
			}

			var wantRequests []string
			for i, tool := range tools {
				allowed := !tc.readOnly || tool.readOnly
				hints, listed := discovered[tool.name]
				delete(discovered, tool.name)
				if listed != allowed {
					t.Errorf("%s listed = %t, want %t", tool.name, listed, allowed)
				}
				if listed {
					for hint, want := range map[string]bool{"readOnlyHint": tool.readOnly, "destructiveHint": tool.destructive} {
						if got := hints[hint]; got == nil || *got != want {
							t.Errorf("%s: %s must be explicitly %t", tool.name, hint, want)
						}
					}
				}
				var result ToolCallResult
				read(i+3, &result)
				if allowed {
					wantRequests = append(wantRequests, tool.request)
					if result.IsError || len(result.Content) != 1 || result.Content[0].Text != "[]" {
						t.Errorf("%s call failed: %+v", tool.name, result)
					}
				} else if !result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "read-only") {
					t.Errorf("%s was not rejected in read-only mode: %+v", tool.name, result)
				}
			}
			if len(discovered) != 0 {
				t.Errorf("tools missing classification expectations: %v", discovered)
			}
			var unknown ToolCallResult
			read(len(tools)+3, &unknown)
			if !unknown.IsError || len(unknown.Content) != 1 || !strings.Contains(unknown.Content[0].Text, "Unknown tool") {
				t.Errorf("unknown tool was not rejected: %+v", unknown)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(requests, wantRequests) {
				t.Errorf("outbound requests = %v, want %v", requests, wantRequests)
			}
		})
	}
}
