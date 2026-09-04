package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Handler success paths. The handlers call os.Exit on any failure, so every
// case here gives the recording server a valid 200 body and asserts on the
// request the handler actually sent (or the value it returned/printed).

func TestHandleTrailStartSendsGitFieldsAndCommitter(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"trail-1"}`)
	handleTrail(cfg(srv), []string{
		"start", "--flow", "flow-1", "--trail", "build-42",
		"--repository", "https://github.com/acme/app", "--commit", "abc123",
		"--branch", "main", "--message", "fix: thing", "--committer", "dev@acme.com",
	})

	if got.method != "POST" || got.path != "/api/v1/trails" {
		t.Fatalf("method/path = %s %s", got.method, got.path)
	}
	if got.body["flow_id"] != "flow-1" || got.body["name"] != "build-42" {
		t.Errorf("body = %+v", got.body)
	}
	tags, ok := got.body["tags"].(map[string]any)
	if !ok || tags["committer"] != "dev@acme.com" {
		t.Errorf("tags = %v, want committer carried through", got.body["tags"])
	}
}

func TestHandleTrailStartQuietPrintsOnlyID(t *testing.T) {
	srv, _ := recordingServer(t, `{"id":"trail-quiet-1"}`)
	handleTrail(cfg(srv), []string{"start", "--flow", "f1", "--trail", "t1", "--quiet"})
}

func TestHandleTrailStartMissingSubcommandExits(t *testing.T) {
	if os.Getenv("FIDES_SUBPROCESS") == "1" {
		handleTrail(CLIConfig{}, nil)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleTrailStartMissingSubcommandExits")
	cmd.Env = append(os.Environ(), "FIDES_SUBPROCESS=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected the handler to exit non-zero without a start subcommand")
	}
}

func TestHandleArtifactReportFromFileHashesLocally(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := recordingServer(t, `{"id":"art-1"}`)
	handleArtifact(cfg(srv), []string{
		"report", "--trail", "trail-1", "--file", path, "--name", "svc-bin", "--type", "binary",
	})

	want, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.body["sha256"] != want {
		t.Errorf("sha256 = %v, want the file's hash %s", got.body["sha256"], want)
	}
	if got.body["type"] != "binary" {
		t.Errorf("type = %v", got.body["type"])
	}
}

func TestHandleAttestBranchProtectionPostsRepoAndBranch(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleAttest(cfg(srv), []string{
		"branch-protection", "--trail", "trail-1", "--repo", "acme/app", "--branch", "release",
	})
	if got.path != "/api/v1/verify-branch-protection" {
		t.Errorf("path = %s", got.path)
	}
	if got.body["repo"] != "acme/app" || got.body["branch"] != "release" {
		t.Errorf("body = %+v", got.body)
	}
}

func TestHandleAttestPlainPayloadUploadsMultipart(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"att-1"}`)
	handleAttest(cfg(srv), []string{
		"--trail", "trail-1", "--name", "manual-check", "--type", "custom", "--payload", `{"ok":true}`,
	})
	if got.path != "/api/v1/attestations" {
		t.Errorf("path = %s, want the attestations endpoint", got.path)
	}
	if !strings.Contains(got.raw, "manual-check") {
		t.Errorf("multipart body missing the attestation name: %q", got.raw)
	}
}

func TestHandleAttestEvidenceFormatParsesJUnitReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "results.xml")
	junit := `<testsuites><testsuite name="s"><testcase name="ok" classname="c"/></testsuite></testsuites>`
	if err := os.WriteFile(report, []byte(junit), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := recordingServer(t, `{"id":"att-2"}`)
	handleAttest(cfg(srv), []string{"junit", "--trail", "trail-1", "--file", report})
	if got.path != "/api/v1/attestations" {
		t.Errorf("path = %s", got.path)
	}
	if !strings.Contains(got.raw, `name="type_name"`) || !strings.Contains(got.raw, "junit") {
		t.Errorf("body should carry type_name=junit: %q", got.raw)
	}
}

func TestHandleAttestFetchPostsProvenanceRequest(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleAttest(cfg(srv), []string{
		"fetch", "--trail", "trail-1", "--artifact-sha", strings.Repeat("a", 64), "--provider", "github",
	})
	if got.path != "/api/v1/attest/fetch" {
		t.Errorf("path = %s", got.path)
	}
	if got.body["provider"] != "github" {
		t.Errorf("provider = %v", got.body["provider"])
	}
}

func TestHandleAttestSBOMParsesAndUploads(t *testing.T) {
	dir := t.TempDir()
	bom := filepath.Join(dir, "bom.json")
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`
	if err := os.WriteFile(bom, []byte(cdx), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := recordingServer(t, `{"id":"att-3"}`)
	handleAttest(cfg(srv), []string{
		"sbom", "--file", bom, "--artifact-sha", strings.Repeat("b", 64),
	})
	if got.path != "/api/v1/attestations" {
		t.Errorf("path = %s", got.path)
	}
	if !strings.Contains(got.raw, "sbom-cyclonedx") {
		t.Errorf("body should carry type_name=sbom-cyclonedx: %q", got.raw)
	}
}

func TestHandleAssertCompliantPasses(t *testing.T) {
	srv, got := recordingServer(t, `{"compliant":true,"violations":[]}`)
	handleAssert(cfg(srv), []string{"--sha256", strings.Repeat("c", 64), "--policy", "prod"})
	if got.method != "GET" {
		t.Errorf("method = %s, want GET", got.method)
	}
	if !strings.Contains(got.query, "policy=prod") {
		t.Errorf("query = %q, want the policy filter", got.query)
	}
}

func TestHandleTrainingRecordAndList(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleTraining(cfg(srv), []string{"record", "--person", "alice", "--course", "owasp-top-10"})
	if got.path != "/api/v1/training" || got.body["person"] != "alice" {
		t.Errorf("record request = %+v %s", got.body, got.path)
	}

	srv2, got2 := recordingServer(t, `[]`)
	handleTraining(cfg(srv2), []string{"list"})
	if got2.method != "GET" || got2.path != "/api/v1/training" {
		t.Errorf("list request = %s %s", got2.method, got2.path)
	}
}

func TestHandleServiceSetAndList(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleService(cfg(srv), []string{"set", "--name", "payments-api", "--owner", "team-pay", "--tier", "2"})
	if got.body["service"] != "payments-api" || got.body["tier"] != float64(2) {
		t.Errorf("body = %+v", got.body)
	}

	srv2, got2 := recordingServer(t, `[]`)
	handleService(cfg(srv2), []string{"list"})
	if got2.path != "/api/v1/services" {
		t.Errorf("path = %s", got2.path)
	}
}

func TestHandleExceptionCreateListRevoke(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"exc-1"}`)
	handleException(cfg(srv), []string{
		"create", "--control", "SOC2-CC6.1", "--reason", "vendor patch pending", "--days", "7",
	})
	if got.body["control_key"] != "SOC2-CC6.1" || got.body["expires_in_days"] != float64(7) {
		t.Errorf("create body = %+v", got.body)
	}

	srv2, got2 := recordingServer(t, `[]`)
	handleException(cfg(srv2), []string{"list"})
	if got2.path != "/api/v1/exceptions" {
		t.Errorf("list path = %s", got2.path)
	}

	srv3, got3 := recordingServer(t, `{"status":"revoked"}`)
	handleException(cfg(srv3), []string{"revoke", "--id", "exc-1"})
	if got3.path != "/api/v1/exceptions/exc-1/revoke" {
		t.Errorf("revoke path = %s", got3.path)
	}
}

func TestHandleEnvCreateAndList(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"env-1"}`)
	handleEnvCreate(cfg(srv), []string{"--name", "prod", "--type", "k8s", "--description", "production"})
	if got.body["name"] != "prod" || got.body["type"] != "k8s" {
		t.Errorf("body = %+v", got.body)
	}

	srv2, got2 := recordingServer(t, `[]`)
	handleEnvList(cfg(srv2), nil)
	if got2.method != "GET" || got2.path != "/api/v1/environments" {
		t.Errorf("list request = %s %s", got2.method, got2.path)
	}
}
