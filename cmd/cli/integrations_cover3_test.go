package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// handleControl: the branches not already covered by request_contract_test.go
// (add/enforce/import) -- list, coverage, timeline, frameworks, catalog,
// enforce --all-controls (which first lists controls, then enforces each
// key), and archive/unarchive.
func TestHandleControlReadBranches(t *testing.T) {
	t.Run("list without --all hits the plain endpoint", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleControl(cfg(srv), []string{"list"})
		if got.path != "/api/v1/controls" || got.query != "" {
			t.Errorf("path/query = %q?%q, want no include_archived", got.path, got.query)
		}
	})

	t.Run("list --all includes archived", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleControl(cfg(srv), []string{"list", "--all"})
		if !strings.Contains(got.query, "include_archived=true") {
			t.Errorf("query = %q, want include_archived=true", got.query)
		}
	})

	t.Run("coverage gets the coverage endpoint", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleControl(cfg(srv), []string{"coverage"})
		if got.path != "/api/v1/controls/coverage" {
			t.Errorf("path = %q", got.path)
		}
	})

	t.Run("timeline carries key and days", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleControl(cfg(srv), []string{"timeline", "--key", "SOC2-CC7.1", "--days", "30"})
		if !strings.Contains(got.query, "days=30") || !strings.Contains(got.query, "SOC2-CC7.1") {
			t.Errorf("query = %q, want days=30 and the key", got.query)
		}
	})

	t.Run("frameworks lists supported frameworks", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleControl(cfg(srv), []string{"frameworks"})
		if got.path != "/api/v1/frameworks" {
			t.Errorf("path = %q", got.path)
		}
	})

	t.Run("catalog encodes only the filters given", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleControl(cfg(srv), []string{"catalog", "--framework", "SOC2", "--area", "build"})
		if !strings.Contains(got.query, "framework=SOC2") || !strings.Contains(got.query, "area=build") {
			t.Errorf("query = %q, want framework and area", got.query)
		}
		if strings.Contains(got.query, "type=") {
			t.Errorf("query = %q, must not include an empty type filter", got.query)
		}
	})

	t.Run("archive posts to the id's archive endpoint", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleControl(cfg(srv), []string{"archive", "--id", "ctrl-1"})
		if want := "/api/v1/controls/ctrl-1/archive"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("unarchive posts to the id's unarchive endpoint", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleControl(cfg(srv), []string{"unarchive", "--id", "ctrl-1"})
		if want := "/api/v1/controls/ctrl-1/unarchive"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})
}

// enforce --all-controls first lists active controls, then enforces each key
// it finds in turn -- fanning out one POST per control against the same
// recording server, so only the last request survives to inspect. What
// matters here is that it does not blow up with zero controls and that the
// (mocked) list->enforce sequence issues more than one request.
func TestHandleControlEnforceAllControls(t *testing.T) {
	hits := 0
	var lastPath string
	srv := httptestNewServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		lastPath = r.URL.Path
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"key":"SOC2-CC6.1"},{"key":"SOC2-CC7.1"}]`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"enforced"}`))
	})
	handleControl(cfg(srv), []string{"enforce", "--all-controls", "--all-environments"})

	if hits != 3 { // 1 list + 2 enforce
		t.Fatalf("hits = %d, want 3 (one list, one enforce per control)", hits)
	}
	if want := "/api/v1/controls/SOC2-CC7.1/enforce"; lastPath != want {
		t.Errorf("last path = %q, want %q", lastPath, want)
	}
}

func TestHandleControlEnforceAllControlsNoneActive(t *testing.T) {
	srv := httptestNewServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	// Must not panic or exit when there is nothing to enforce.
	handleControl(cfg(srv), []string{"enforce", "--all-controls", "--all-environments"})
}

// handlePolicy: global (create/delete/generate) and per-environment
// (add/list/check) subcommands.
func TestHandlePolicyGlobalSubcommands(t *testing.T) {
	t.Run("create with a rules file reads and posts its contents", func(t *testing.T) {
		dir := t.TempDir()
		rulesPath := filepath.Join(dir, "rules.jq")
		if err := os.WriteFile(rulesPath, []byte(`.summary.failed == 0`), 0o600); err != nil {
			t.Fatal(err)
		}
		srv, got := recordingServer(t, `{}`)
		handlePolicy(cfg(srv), []string{"create", "--name", "no-failures", "--rules-file", rulesPath})
		if got.path != "/api/v1/policies/create" {
			t.Errorf("path = %q", got.path)
		}
		if got.body["rules"] != ".summary.failed == 0" {
			t.Errorf("rules = %v, want the file contents", got.body["rules"])
		}
	})

	t.Run("delete sends a DELETE to the policy id", func(t *testing.T) {
		srv, got := recordingServer(t, `{"deleted":true}`)
		handlePolicy(cfg(srv), []string{"delete", "--id", "pol-1"})
		if got.method != http.MethodDelete || got.path != "/api/v1/policies/pol-1" {
			t.Errorf("got %s %s", got.method, got.path)
		}
	})

	t.Run("generate posts framework and description", func(t *testing.T) {
		srv, got := recordingServer(t, `{"rules":"..."}`)
		handlePolicy(cfg(srv), []string{"generate", "--framework", "SOC2", "--description", "no critical vulns"})
		if want := "/api/v1/ai/generate-policy"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["description"] != "no critical vulns" {
			t.Errorf("description = %v", got.body["description"])
		}
	})
}

func TestHandlePolicyEnvironmentSubcommands(t *testing.T) {
	t.Run("add carries required types, if-tag and if-value", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handlePolicy(cfg(srv), []string{
			"add", "--env", "env-1", "--name", "prod-gate", "--require", "trivy,junit",
			"--if-tag", "environment", "--if-value", "prod",
		})
		if want := "/api/v1/environments/env-1/policies"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		types, ok := got.body["required_types"].([]any)
		if !ok || len(types) != 2 {
			t.Fatalf("required_types = %v, want 2 entries", got.body["required_types"])
		}
		if got.body["if_tag"] != "environment" || got.body["if_value"] != "prod" {
			t.Errorf("if_tag/if_value = %v/%v", got.body["if_tag"], got.body["if_value"])
		}
	})

	t.Run("list gets the environment's policies", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handlePolicy(cfg(srv), []string{"list", "--env", "env-1"})
		if want := "/api/v1/environments/env-1/policies"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("check carries the trail and reports compliant", func(t *testing.T) {
		srv, got := recordingServer(t, `{"compliant":true}`)
		handlePolicy(cfg(srv), []string{"check", "--env", "env-1", "--trail", "t1"})
		if !strings.Contains(got.query, "trail=t1") {
			t.Errorf("query = %q, want trail=t1", got.query)
		}
	})
}

// handleAllowlist: list and remove (add/check are already covered in
// request_contract_test.go).
func TestHandleAllowlistListAndRemove(t *testing.T) {
	t.Run("list gets the environment's allowlist", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleAllowlist(cfg(srv), []string{"list", "--env", "env-1"})
		if want := "/api/v1/environments/env-1/allowlist"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("remove deletes the sha entry", func(t *testing.T) {
		srv, got := recordingServer(t, `{"removed":true}`)
		sha := strings.Repeat("e", 64)
		handleAllowlist(cfg(srv), []string{"remove", "--env", "env-1", "--sha", sha})
		if got.method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", got.method)
		}
		if want := "/api/v1/environments/env-1/allowlist/" + sha; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})
}

// handleRemediation: propose (all three domains), list, get, and the
// approve/reject/apply transitions that share remediationTransition.
func TestHandleRemediationPropose(t *testing.T) {
	t.Run("env_tag requires key=value pairs and posts a map", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleRemediation(cfg(srv), []string{
			"propose", "--env", "env-1", "--domain", "env_tag", "--reason", "policy drift",
			"--tags", "team=payments,pci-scope=false",
		})
		params, ok := got.body["params"].(map[string]any)
		if !ok {
			t.Fatalf("params is %T", got.body["params"])
		}
		tags, ok := params["tags"].(map[string]any)
		if !ok || tags["team"] != "payments" {
			t.Errorf("tags = %v", params["tags"])
		}
	})

	t.Run("allowlist_entry carries the sha", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		sha := strings.Repeat("f", 64)
		handleRemediation(cfg(srv), []string{
			"propose", "--env", "env-1", "--domain", "allowlist_entry", "--sha", sha,
		})
		params, ok := got.body["params"].(map[string]any)
		if !ok || params["artifact_sha256"] != sha {
			t.Errorf("params = %v, want artifact_sha256=%s", got.body["params"], sha)
		}
	})

	t.Run("drift_resync carries the sha too", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		sha := strings.Repeat("1", 64)
		handleRemediation(cfg(srv), []string{
			"propose", "--env", "env-1", "--domain", "drift_resync", "--sha", sha,
		})
		params, ok := got.body["params"].(map[string]any)
		if !ok || params["artifact_sha256"] != sha {
			t.Errorf("params = %v", got.body["params"])
		}
	})
}

func TestHandleRemediationListGetAndTransitions(t *testing.T) {
	t.Run("list carries status and env filters", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleRemediation(cfg(srv), []string{"list", "--status", "proposed", "--env", "env-1"})
		if !strings.Contains(got.query, "status=proposed") || !strings.Contains(got.query, "environment_id=env-1") {
			t.Errorf("query = %q", got.query)
		}
	})

	t.Run("get fetches by id", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleRemediation(cfg(srv), []string{"get", "--id", "rem-1"})
		if want := "/api/v1/remediation/rem-1"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("approve posts to the approve transition", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleRemediation(cfg(srv), []string{"approve", "--id", "rem-1", "--reason", "ok"})
		if want := "/api/v1/remediation/rem-1/approve"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("reject posts to the reject transition", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleRemediation(cfg(srv), []string{"reject", "--id", "rem-1"})
		if want := "/api/v1/remediation/rem-1/reject"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})

	t.Run("apply posts to the apply transition and succeeds without error in the body", func(t *testing.T) {
		srv, got := recordingServer(t, `{"status":"applied"}`)
		handleRemediation(cfg(srv), []string{"apply", "--id", "rem-1"})
		if want := "/api/v1/remediation/rem-1/apply"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})
}

// handleEnvVerify: --rule flags and a --rules-file both contribute rules.
func TestHandleEnvVerify(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesFile, []byte(".pods[].status == \"Ready\"\n\n.pods | length > 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := recordingServer(t, `{"compliant":true}`)
	handleEnvVerify(cfg(srv), []string{
		"--env", "env-1", "--server", "k8s-prod", "--tool", "get_pods",
		"--rule", ".ready == true", "--rules-file", rulesFile,
	})
	if want := "/api/v1/environments/mcp/verify"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	rules, ok := got.body["rules"].([]any)
	if !ok || len(rules) != 3 {
		t.Fatalf("rules = %v, want 3 entries (1 --rule + 2 from the file)", got.body["rules"])
	}
}

// handleEnvDiff: the plain snapshot diff, and the --reevaluate-change path.
func TestHandleEnvDiff(t *testing.T) {
	t.Run("plain diff carries from/to as query params", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleEnvDiff(cfg(srv), []string{"--env", "env-1", "--from", "snap-a", "--to", "snap-b"})
		if got.method != http.MethodGet {
			t.Errorf("method = %s, want GET", got.method)
		}
		if !strings.Contains(got.query, "from=snap-a") || !strings.Contains(got.query, "to=snap-b") {
			t.Errorf("query = %q", got.query)
		}
	})

	t.Run("reevaluate-change posts to the reevaluate endpoint", func(t *testing.T) {
		srv, got := recordingServer(t, `{"drift_detected":false}`)
		handleEnvDiff(cfg(srv), []string{"--env", "env-1", "--reevaluate-change", "CHG0030192"})
		if want := "/api/v1/environments/env-1/snapshots/reevaluate-change"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["change_number"] != "CHG0030192" {
			t.Errorf("change_number = %v", got.body["change_number"])
		}
	})
}

// httptestNewServer starts a server that answers with a custom handler --
// needed for the --all-controls test, which must answer the initial list GET
// differently from the per-control enforce POSTs that follow.
func httptestNewServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv
}
