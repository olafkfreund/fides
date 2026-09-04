package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// handleFlagChange: record must POST the flag identity and transition;
// list must GET with the limit carried through.
func TestHandleFlagChange(t *testing.T) {
	t.Run("record posts the flag transition", func(t *testing.T) {
		srv, got := recordingServer(t, `{"status":"ok"}`)
		handleFlagChange(cfg(srv), []string{
			"record", "--flag-key", "new-checkout", "--env", "prod",
			"--from", "off", "--to", "on", "--source", "unleash",
		})
		if want := "/api/v1/flags/changed"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["flag_key"] != "new-checkout" {
			t.Errorf("flag_key = %v", got.body["flag_key"])
		}
		if got.body["new_state"] != "on" {
			t.Errorf("new_state = %v, want on", got.body["new_state"])
		}
	})

	t.Run("list carries the limit", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleFlagChange(cfg(srv), []string{"list", "--limit", "5"})
		if got.method != http.MethodGet {
			t.Errorf("method = %s, want GET", got.method)
		}
		if !strings.Contains(got.query, "limit=5") {
			t.Errorf("query = %q, want limit=5", got.query)
		}
	})
}

// handleServiceNow covers every subcommand's request shape in one pass.
func TestHandleServiceNowSubcommands(t *testing.T) {
	t.Run("config posts instance settings", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{
			"config", "--instance-url", "https://acme.service-now.com",
			"--client-id", "cid", "--secret-path", "env:SN_SECRET",
		})
		if want := "/api/v1/tenant/servicenow"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["instance_url"] != "https://acme.service-now.com" {
			t.Errorf("instance_url = %v", got.body["instance_url"])
		}
	})

	t.Run("get fetches the saved config", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"get"})
		if got.method != http.MethodGet || got.path != "/api/v1/tenant/servicenow" {
			t.Errorf("got %s %s, want GET /api/v1/tenant/servicenow", got.method, got.path)
		}
	})

	t.Run("change-check carries the trail and change", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"change-check", "--trail", "t1", "--change", "CHG001"})
		if got.body["trail_id"] != "t1" || got.body["change_number"] != "CHG001" {
			t.Errorf("body = %v", got.body)
		}
	})

	t.Run("link-control carries trail, change and control", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{
			"link-control", "--trail", "t1", "--change", "CHG001", "--control", "SOC2-CC7.1",
		})
		if want := "/api/v1/servicenow/link-control"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["control"] != "SOC2-CC7.1" {
			t.Errorf("control = %v", got.body["control"])
		}
	})

	t.Run("anchor-deployment resolves via ci fallback", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"anchor-deployment", "--trail", "t1", "--ci", "app-server-01"})
		if got.body["ci"] != "app-server-01" {
			t.Errorf("ci = %v", got.body["ci"])
		}
	})

	t.Run("grounding queries by change", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"grounding", "--change", "CHG001"})
		if !strings.Contains(got.query, "CHG001") {
			t.Errorf("query = %q, want the change number", got.query)
		}
	})
}

// handleServiceNowMCP: servers/lookup/tools/call.
func TestHandleServiceNowMCP(t *testing.T) {
	t.Run("servers lists discovered MCP servers", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleServiceNow(cfg(srv), []string{"mcp", "servers"})
		if got.method != http.MethodGet {
			t.Errorf("method = %s, want GET", got.method)
		}
	})

	t.Run("lookup carries table and query", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{
			"mcp", "lookup", "--table", "change_request", "--query", "number=CHG001",
		})
		if got.body["table"] != "change_request" {
			t.Errorf("table = %v", got.body["table"])
		}
	})

	t.Run("tools requests a server's tool list", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"mcp", "tools", "--server", "sn1"})
		if got.body["server"] != "sn1" {
			t.Errorf("server = %v", got.body["server"])
		}
	})

	t.Run("call parses --args as JSON and attaches it", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{
			"mcp", "call", "--tool", "get_incident", "--args", `{"number":"INC001"}`,
		})
		if got.body["tool"] != "get_incident" {
			t.Errorf("tool = %v", got.body["tool"])
		}
		args, ok := got.body["arguments"].(map[string]any)
		if !ok {
			t.Fatalf("arguments is %T, want an object", got.body["arguments"])
		}
		if args["number"] != "INC001" {
			t.Errorf("arguments.number = %v", args["number"])
		}
	})

	t.Run("call without --args sends no arguments field", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleServiceNow(cfg(srv), []string{"mcp", "call", "--tool", "get_incident"})
		if _, ok := got.body["arguments"]; ok {
			t.Error("arguments must not be sent when --args was not given")
		}
	})
}

func TestHandleGitProviderConfig(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	handleGitProvider(cfg(srv), []string{
		"config", "--provider", "github", "--host", "github.com",
		"--api-base", "https://api.github.com", "--token-path", "env:GH_TOKEN",
	})
	if want := "/api/v1/tenant/git-providers"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["provider"] != "github" {
		t.Errorf("provider = %v", got.body["provider"])
	}
}

// A webhook's --events splits into a real list; empty means "all", which
// must arrive as an empty/absent list rather than a list containing "".
func TestHandleWebhookConfig(t *testing.T) {
	t.Run("splits events on comma", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleWebhook(cfg(srv), []string{
			"config", "--name", "ci-hook", "--url", "https://example.com/hook",
			"--secret-path", "env:HOOK_SECRET", "--events", "trail.completed,control.violated",
		})
		types, ok := got.body["event_types"].([]any)
		if !ok || len(types) != 2 {
			t.Fatalf("event_types = %v, want 2 entries", got.body["event_types"])
		}
	})

	t.Run("empty events sends no event types", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleWebhook(cfg(srv), []string{
			"config", "--name", "ci-hook", "--url", "https://example.com/hook",
			"--secret-path", "env:HOOK_SECRET",
		})
		if v, ok := got.body["event_types"]; ok && v != nil {
			t.Errorf("event_types = %v, want nil/absent for the default (all events)", v)
		}
	})
}

func TestHandleSlackConfig(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	handleSlack(cfg(srv), []string{"config", "--secret-path", "env:SLACK_WEBHOOK"})
	if got.body["webhook_secret_path"] != "env:SLACK_WEBHOOK" {
		t.Errorf("webhook_secret_path = %v", got.body["webhook_secret_path"])
	}
	if got.body["enabled"] != true {
		t.Errorf("enabled = %v, want true by default", got.body["enabled"])
	}
}

// Approve carries the SoD role it represents; the default is "approver" but
// "deployer" must survive unchanged.
func TestHandleApprove(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	handleApprove(cfg(srv), []string{"--trail", "t1", "--reason", "looks good", "--role", "deployer"})
	if want := "/api/v1/trails/t1/approvals"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["role"] != "deployer" {
		t.Errorf("role = %v, want deployer", got.body["role"])
	}
}

// Audit downloads the trail's package to disk; the default filename encodes
// the trail id, and an explicit --output must be honored instead.
func TestHandleAuditDownloadsToFile(t *testing.T) {
	srv, got := recordingServer(t, "zip-bytes-stand-in")
	dir := t.TempDir()
	out := filepath.Join(dir, "custom.zip")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	handleAudit(cfg(srv), []string{"--trail", "t1", "--output", out})

	if want := "/api/v1/trails/t1/audit-package"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected the audit package to be written: %v", err)
	}
	if string(data) != "zip-bytes-stand-in" {
		t.Errorf("file contents = %q", string(data))
	}
}

func TestHandleLogicalEnvSubcommands(t *testing.T) {
	t.Run("create posts the name", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleLogicalEnv(cfg(srv), []string{"create", "--name", "payments-logical"})
		if got.body["name"] != "payments-logical" {
			t.Errorf("name = %v", got.body["name"])
		}
	})
	t.Run("list gets the collection", func(t *testing.T) {
		srv, got := recordingServer(t, `[]`)
		handleLogicalEnv(cfg(srv), []string{"list"})
		if got.method != http.MethodGet || got.path != "/api/v1/logical-environments" {
			t.Errorf("got %s %s", got.method, got.path)
		}
	})
	t.Run("add-member posts the physical env under the logical id", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleLogicalEnv(cfg(srv), []string{"add-member", "--id", "le1", "--env", "env1"})
		if want := "/api/v1/logical-environments/le1/members"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["environment_id"] != "env1" {
			t.Errorf("environment_id = %v", got.body["environment_id"])
		}
	})
	t.Run("state gets the logical id's state", func(t *testing.T) {
		srv, got := recordingServer(t, `{}`)
		handleLogicalEnv(cfg(srv), []string{"state", "--id", "le1"})
		if want := "/api/v1/logical-environments/le1/state"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
	})
}

func TestHandleUserSetPassword(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	handleUser(cfg(srv), []string{"set-password", "--user", "u1", "--password", "longenoughpassword"})
	if want := "/api/v1/tenant/users/u1/password"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
}

func TestHandleAnchor(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	handleAnchor(cfg(srv), []string{"--trail", "t1", "--tsa", "https://tsa.example.com"})
	if want := "/api/v1/trails/t1/anchor"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["tsa_url"] != "https://tsa.example.com" {
		t.Errorf("tsa_url = %v", got.body["tsa_url"])
	}
}

func TestHandleVerifyChain(t *testing.T) {
	srv, got := recordingServer(t, `{"valid":true}`)
	handleVerifyChain(cfg(srv), []string{"--trail", "t1"})
	if want := "/api/v1/trails/t1/verify-chain"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
}

func TestHandleAttestFetch(t *testing.T) {
	srv, got := recordingServer(t, `{}`)
	sha := strings.Repeat("d", 64)
	handleAttestFetch(cfg(srv), []string{
		"--trail", "t1", "--artifact-sha", sha, "--provider", "github", "--repo", "acme/app",
	})
	if want := "/api/v1/attest/fetch"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["artifact_sha256"] != sha {
		t.Errorf("artifact_sha256 = %v", got.body["artifact_sha256"])
	}
	if got.body["provider"] != "github" {
		t.Errorf("provider = %v", got.body["provider"])
	}
}

// handleAttestEvidence parses a real JUnit report and multipart-uploads it.
func TestHandleAttestEvidenceJUnit(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "junit.xml")
	xml := `<testsuites><testsuite name="s"><testcase name="ok" classname="c"></testcase></testsuite></testsuites>`
	if err := os.WriteFile(report, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, got := recordingServer(t, `{"id":"att-1"}`)
	handleAttestEvidence(cfg(srv), "junit", []string{"--trail", "t1", "--file", report})

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if !strings.Contains(got.path, "/api/v1/attestations") {
		t.Errorf("path = %q, want the attestations endpoint", got.path)
	}
	if !strings.Contains(got.raw, "junit") {
		t.Errorf("multipart body does not mention junit type: %q", got.raw)
	}
}

// handleAttestAuthorship reads the current repo's HEAD commit -- this test
// runs inside a real git checkout, so it exercises gitOutput for real rather
// than stubbing it.
func TestHandleAttestAuthorship(t *testing.T) {
	// This is the one test here that shells out to git, and handleAttestAuthorship
	// calls fail() -- os.Exit -- when git errors. That would take the whole
	// cmd/cli test binary down and mask every other test rather than failing one,
	// so check git is usable first and skip if it is not. `log -1` and `rev-parse`
	// both work in CI's depth-1 checkout; this guards the container cases (not a
	// repo, dubious ownership) where the failure would otherwise be silent.
	if err := exec.Command("git", "rev-parse", "HEAD").Run(); err != nil {
		t.Skipf("git unusable here, and this handler exits on git failure: %v", err)
	}

	srv, got := recordingServer(t, `{"id":"att-2"}`)
	handleAttestAuthorship(cfg(srv), []string{"--trail", "t1", "--reviewer", "alice"})

	if !strings.Contains(got.path, "/api/v1/attestations") {
		t.Errorf("path = %q, want the attestations endpoint", got.path)
	}
	if !strings.Contains(got.raw, "code.authorship") {
		t.Errorf("multipart body does not carry the type_name: %q", got.raw)
	}
	if !strings.Contains(got.raw, "alice") {
		t.Errorf("multipart body does not carry the reviewer override: %q", got.raw)
	}
}

func TestGitOutputReadsHEAD(t *testing.T) {
	sha, err := gitOutput("rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("gitOutput: %v", err)
	}
	if strings.TrimSpace(sha) == "" {
		t.Error("expected a non-empty commit sha")
	}
}
