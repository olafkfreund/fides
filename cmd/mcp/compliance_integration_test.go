package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"fides/pkg/api"
	"fides/pkg/db"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestMCPComplianceIntegration(t *testing.T) {
	if os.Getenv("FIDES_MCP_TEST_PROCESS") == "1" {
		main()
		os.Exit(0)
	}

	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to exercise the MCP compliance tool against the API")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	digest := "sha256:" + uuid.NewString()
	t.Cleanup(func() {
		if _, err := pool.Exec("DELETE FROM organizations WHERE id = $1", org); err != nil {
			t.Error(err)
		}
	})
	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	seed("INSERT INTO organizations (id, name) VALUES ($1, $2)", org, org.String())
	seed("INSERT INTO flows (id, org_id, name) VALUES ($1, $2, 'flow')", flow, org)
	seed("INSERT INTO trails (id, flow_id, name) VALUES ($1, $2, 'trail')", trail, flow)
	seed("INSERT INTO artifacts (sha256, org_id, trail_id, name, type) VALUES ($1, $2, $3, 'fixture image', 'docker')", digest, org, trail)
	seed("INSERT INTO attestation_types (org_id, name, jq_rules) VALUES ($1, 'test-result', ARRAY['.passed == true'])", org)

	token := uuid.NewString()
	t.Setenv("FIDES_API_TOKEN", token)
	t.Setenv("FIDES_API_ORG_ID", org.String())
	routes := api.NewServer(pool, nil, nil).Routes()

	query := url.Values{"sha256": {digest}}.Encode()
	errorDigest := "sha256:" + uuid.NewString()
	errorQuery := url.Values{"sha256": {errorDigest}}.Encode()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance?"+query+"&policy=&policy=prod", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rejected := httptest.NewRecorder()
	routes.ServeHTTP(rejected, req)
	if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), "policy selector is unsupported") {
		t.Fatalf("policy selector: HTTP %d, body %s", rejected.Code, rejected.Body.String())
	}

	attestation := map[string]string{
		"trail_id":        trail.String(),
		"artifact_sha256": digest,
		"name":            "unit tests",
		"type_name":       "test-result",
		"payload":         `{"passed":false}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/compliance":
			if r.Method == http.MethodGet && r.URL.RawQuery == errorQuery {
				http.Error(w, "fixture service unavailable", http.StatusServiceUnavailable)
				return
			}
			if r.Method != http.MethodGet || r.URL.RawQuery != query {
				t.Errorf("compliance request: %s %s, want GET with %s", r.Method, r.URL, query)
			}
		case "/api/v1/attestations":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				http.Error(w, "reading fixture body", http.StatusBadRequest)
				return
			}
			var sent map[string]string
			if err := json.Unmarshal(body, &sent); err != nil || !maps.Equal(sent, attestation) {
				t.Errorf("attestation request JSON: %s, want %v", body, attestation)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		routes.ServeHTTP(w, r)
	}))
	defer server.Close()

	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	send := func(id int, method string, params any) {
		t.Helper()
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
	}
	check := map[string]any{"name": "check_compliance", "arguments": map[string]string{"artifact_sha256": digest}}
	report := maps.Clone(attestation)
	report["is_compliant"] = "true"
	send(1, "tools/list", nil)
	send(2, "tools/call", check)
	send(3, "tools/call", map[string]any{"name": "report_attestation", "arguments": report})
	send(4, "tools/call", check)
	send(5, "tools/call", map[string]any{"name": "check_compliance", "arguments": map[string]string{"artifact_sha256": errorDigest}})

	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPComplianceIntegration$")
	cmd.Env = append(os.Environ(), "FIDES_MCP_TEST_PROCESS=1", "FIDES_SERVER_URL="+server.URL)
	cmd.Stdin = &input
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	read := func(id int, result any) {
		t.Helper()
		reply := struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}{}
		if err := decoder.Decode(&reply); err != nil {
			t.Fatalf("decode reply %d: %v (output %q)", id, err, output)
		}
		if reply.ID != id || len(reply.Error) != 0 {
			t.Fatalf("reply %d: got id %d, error %s", id, reply.ID, reply.Error)
		}
		if err := json.Unmarshal(reply.Result, result); err != nil {
			t.Fatal(err)
		}
	}
	var list ToolsListResult
	read(1, &list)
	var foundReport bool
	for _, tool := range list.Tools {
		if tool.Name == "report_attestation" {
			foundReport = true
			prop := tool.InputSchema.Properties["is_compliant"]
			if prop.Type != "string" || !strings.Contains(prop.Description, "Deprecated and ignored") {
				t.Errorf("legacy argument description: %+v", prop)
			}
			for _, field := range tool.InputSchema.Required {
				if field == "is_compliant" {
					t.Error("legacy argument must be optional")
				}
			}
		}
	}
	if !foundReport {
		t.Fatal("report_attestation was missing from tools/list")
	}
	for _, want := range []struct {
		id    int
		field string
		value bool
	}{
		{2, "compliant", true},
		{3, "is_compliant", false},
		{4, "compliant", false},
	} {
		var result ToolCallResult
		read(want.id, &result)
		if result.IsError || len(result.Content) != 1 {
			t.Fatalf("tool call %d failed: %+v", want.id, result)
		}
		var verdict map[string]any
		if err := json.Unmarshal([]byte(result.Content[0].Text), &verdict); err != nil {
			t.Fatal(err)
		}
		if verdict[want.field] != want.value {
			t.Errorf("tool call %d: %s = %v, want %t", want.id, want.field, verdict[want.field], want.value)
		}
	}
	var failure ToolCallResult
	read(5, &failure)
	if !failure.IsError || len(failure.Content) != 1 ||
		!strings.Contains(failure.Content[0].Text, "503") || !strings.Contains(failure.Content[0].Text, "fixture service unavailable") {
		t.Fatalf("HTTP error was not returned as an MCP tool error: %+v", failure)
	}
	if err := decoder.Decode(&json.RawMessage{}); err != io.EOF {
		t.Fatalf("unexpected output after the last reply: %v", err)
	}
}
