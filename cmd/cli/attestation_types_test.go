package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAttestationTypeCommands(t *testing.T) {
	const id = "d46a8b50-f5a0-414b-83dc-4d60a0cc6302"
	const schema = "{ \"type\": \"object\" }\n"
	file := filepath.Join(t.TempDir(), "schema.json")
	if err := os.WriteFile(file, []byte(schema), 0600); err != nil {
		t.Fatal(err)
	}
	const itemPath = attestationTypesPath + "/" + id
	tests := []struct {
		args         []string
		method, path string
		payload      map[string]any
	}{
		{[]string{"create", "--name", "release", "--schema", file, "--jq-rules", `[".passed"]`}, "POST", attestationTypesPath, map[string]any{"name": "release", "schema": schema, "jq_rules": []any{".passed"}}},
		{[]string{"create", "--name", "release"}, "POST", attestationTypesPath, map[string]any{"name": "release"}},
		{[]string{"get", "--id", id}, "GET", itemPath, nil},
		{[]string{"update", "--id", id, "--description", ""}, "PATCH", itemPath, map[string]any{"description": ""}},
		{[]string{"update", "--id", id, "--schema", file}, "PATCH", itemPath, map[string]any{"schema": schema}},
		{[]string{"update", "--id", id, "--clear-schema", "--jq-rules", "[]"}, "PATCH", itemPath, map[string]any{"schema": "", "jq_rules": []any{}}},
		{[]string{"delete", "--id", id}, "DELETE", itemPath, nil},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.args), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method || r.URL.Path != tt.path || r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				if tt.payload != nil {
					var got map[string]any
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, tt.payload) {
						t.Errorf("payload = %v, %v, want %v", got, err, tt.payload)
					}
				}
				if r.Method == "DELETE" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				fmt.Fprint(w, `{"id":"`+id+`"}`)
			}))
			defer server.Close()
			if _, err := attestationTypeCommand(CLIConfig{ServerURL: server.URL, Token: "token"}, tt.args); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := attestationTypeCommand(CLIConfig{}, []string{"update", "--id", id, "--schema", file, "--clear-schema"}); err == nil {
		t.Fatal("expected conflicting schema flags to fail")
	}
}

func TestAttestationTypeListFollowsPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != attestationTypesPath || r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.URL.Query().Get("cursor") == "next" {
			fmt.Fprint(w, `[{"name":"second"}]`)
			return
		}
		w.Header().Set("Link", "<"+attestationTypesPath+`?cursor=next>; rel="next"`)
		fmt.Fprint(w, `[{"name":"first"}]`)
	}))
	defer server.Close()

	got, err := attestationTypeCommand(CLIConfig{ServerURL: server.URL, Token: "token"}, []string{"list"})
	if err != nil || got != `[{"name":"first"},{"name":"second"}]` {
		t.Fatalf("list = %q, %v", got, err)
	}
}
