package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What these are for.
//
// Two bugs shipped from this package in one week, and both were the same shape:
// the command built the wrong request and nothing noticed. `fides env archive`
// was called as though `fides` were the CLI when it was a curl wrapper, so it
// never once ran; and `allowlist --image` was documented as covering an image's
// future digests when it resolves one digest at that moment.
//
// Neither was a logic error inside a function. Both were the command sending
// something other than what it should have. So these tests assert on the
// request that leaves the CLI -- method, path, and body -- by running the real
// handler against a server that records what arrived.
//
// The handlers call os.Exit on failure, which would take the test binary with
// them. They only do that on error, so every case here returns a success status
// and asserts on what the CLI sent to get it.

type captured struct {
	method string
	path   string
	query  string
	body   map[string]any
	raw    string
	hits   int
}

// recordingServer answers every request with 200 and the supplied body, and
// records the last request it saw.
func recordingServer(t *testing.T, reply string) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.hits++
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		got.raw = string(b)
		if len(b) > 0 {
			_ = json.Unmarshal(b, &got.body)
		}
		w.Header().Set("Content-Type", "application/json")
		if reply == "" {
			reply = "{}"
		}
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func cfg(srv *httptest.Server) CLIConfig {
	return CLIConfig{ServerURL: srv.URL, Token: "test-token"}
}

// The bug: this was called as `fides env archive --env <id>` where `fides` was
// a curl wrapper, producing a request with no URL in it at all. The command
// must POST to the environment's archive endpoint.
func TestEnvArchivePostsToArchiveEndpoint(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok","archived":true}`)
	handleEnvArchive(cfg(srv), []string{"--env", "abc-123"}, true)

	if got.hits != 1 {
		t.Fatalf("expected exactly one request, got %d", got.hits)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if want := "/api/v1/environments/abc-123/archive"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
}

// Unarchive is the same command with the verb flipped. A copy-paste that left
// it posting to /archive would be invisible without this.
func TestEnvUnarchivePostsToUnarchiveEndpoint(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok","archived":false}`)
	handleEnvArchive(cfg(srv), []string{"--env", "abc-123"}, false)

	if want := "/api/v1/environments/abc-123/unarchive"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
}

// Enforcing a control writes an environment policy. The distinction between one
// environment and all of them is a single field, and getting it wrong either
// under-applies a control silently or applies it everywhere by surprise.
func TestControlEnforceSendsEnvironmentOrAll(t *testing.T) {
	t.Run("single environment", func(t *testing.T) {
		srv, got := recordingServer(t, `{"status":"enforced","environments":1}`)
		handleControl(cfg(srv), []string{"enforce", "--key", "SOC2-CC7.1", "--env", "env-1"})

		if want := "/api/v1/controls/SOC2-CC7.1/enforce"; got.path != want {
			t.Errorf("path = %q, want %q", got.path, want)
		}
		if got.body["environment_id"] != "env-1" {
			t.Errorf("environment_id = %v, want env-1", got.body["environment_id"])
		}
		if _, ok := got.body["all"]; ok {
			t.Error(`"all" must not be sent when a single environment was named`)
		}
	})

	t.Run("all environments", func(t *testing.T) {
		srv, got := recordingServer(t, `{"status":"enforced","environments":10}`)
		handleControl(cfg(srv), []string{"enforce", "--key", "SOC2-CC7.1", "--all-environments"})

		if got.body["all"] != true {
			t.Errorf(`"all" = %v, want true`, got.body["all"])
		}
		if _, ok := got.body["environment_id"]; ok {
			t.Error("environment_id must not be sent alongside all")
		}
	})
}

// A control IS its list of evidence types, so --require has to arrive as a
// list. Sending "junit,trivy" as one string would create a control requiring a
// single evidence type nothing will ever produce -- stuck at 0% forever, with
// no error anywhere.
func TestControlAddSplitsRequiredTypes(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"saved"}`)
	handleControl(cfg(srv), []string{
		"add", "--key", "ACME-1", "--name", "Test control",
		"--require", "junit,trivy,sbom-cyclonedx",
	})

	if want := "/api/v1/controls"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	types, ok := got.body["required_types"].([]any)
	if !ok {
		t.Fatalf("required_types is %T, want a list -- a comma string here is a control that can never be satisfied", got.body["required_types"])
	}
	if len(types) != 3 {
		t.Fatalf("required_types = %v, want 3 entries", types)
	}
	for i, want := range []string{"junit", "trivy", "sbom-cyclonedx"} {
		if types[i] != want {
			t.Errorf("required_types[%d] = %v, want %s", i, types[i], want)
		}
	}
}

// Importing a framework must name the framework. Posting an empty one would
// import nothing and report success.
func TestControlImportSendsFramework(t *testing.T) {
	srv, got := recordingServer(t, `{"imported":5}`)
	handleControl(cfg(srv), []string{"import", "--framework", "SOC2"})

	if want := "/api/v1/controls/import-framework"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["framework"] != "SOC2" {
		t.Errorf("framework = %v, want SOC2", got.body["framework"])
	}
}

// An allow-list entry records an accepted risk. The reason is the whole point:
// an entry with no stated reason cannot be re-evaluated later by anyone,
// including whoever added it.
func TestAllowlistAddSendsDigestAndReason(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	sha := strings.Repeat("a", 64)
	handleAllowlist(cfg(srv), []string{
		"add", "--env", "env-1", "--sha", sha, "--reason", "vendor base image, reviewed",
	})

	if want := "/api/v1/environments/env-1/allowlist"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.body["artifact_sha256"] != sha {
		t.Errorf("artifact_sha256 = %v, want the digest", got.body["artifact_sha256"])
	}
	if got.body["reason"] != "vendor base image, reviewed" {
		t.Errorf("reason = %v, want it carried through", got.body["reason"])
	}
}

// allowlist check is a deploy gate, so it must ask about the digest it was
// given. A query that drops the sha would answer about the wrong thing.
func TestAllowlistCheckQueriesTheDigest(t *testing.T) {
	srv, got := recordingServer(t, `{"approved":true}`)
	sha := strings.Repeat("b", 64)
	handleAllowlist(cfg(srv), []string{"check", "--env", "env-1", "--sha", sha})

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if !strings.Contains(got.query, "sha="+sha) {
		t.Errorf("query = %q, want it to carry sha=%s", got.query, sha)
	}
}

// Every command must present the operator's token. A request that silently
// drops it gets a 401 that looks like a server problem.
func TestCommandsSendTheBearerToken(t *testing.T) {
	var authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(srv.Close)

	handleEnvArchive(CLIConfig{ServerURL: srv.URL, Token: "secret-token"}, []string{"--env", "e1"}, true)
	if authz != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want a Bearer token", authz)
	}
}
