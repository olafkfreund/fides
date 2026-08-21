package main

import (
	"net/http"
	"strings"
	"testing"
)

// More of the same contract: what leaves the CLI when an operator types a
// command. Grouped separately from request_contract_test.go only to keep each
// file readable.

// The three commands a pipeline runs on every build. If any of them sends the
// wrong thing, evidence is recorded against the wrong trail or not at all --
// and the gate downstream still says "pass", because the gate can only judge
// what it was given.
func TestPipelineCommandsSendTheirIdentifiers(t *testing.T) {
	t.Run("artifact report carries digest and name", func(t *testing.T) {
		srv, got := recordingServer(t, `{"id":"art-1"}`)
		sha := strings.Repeat("c", 64)
		handleArtifact(cfg(srv), []string{
			"report", "--trail", "trail-1", "--sha256", sha,
			"--name", "payments-api", "--type", "docker",
		})
		if got.body["sha256"] != sha {
			t.Errorf("sha256 = %v, want the digest by value", got.body["sha256"])
		}
		if got.body["name"] != "payments-api" {
			t.Errorf("name = %v, want payments-api", got.body["name"])
		}
		if got.body["type"] != "docker" {
			t.Errorf("type = %v, want docker", got.body["type"])
		}
	})

	t.Run("change gate asks about the trail it was given", func(t *testing.T) {
		srv, got := recordingServer(t, `{"verdict":"allow","risk_score":10}`)
		handleChangeGate(cfg(srv), []string{"--trail", "trail-42"})
		if !strings.Contains(got.path+"?"+got.query, "trail-42") {
			t.Errorf("request %q%q does not mention the trail", got.path, got.query)
		}
	})
}

// A framework report is what an auditor receives. Asking for the wrong
// framework, or dropping the format, produces a document that looks right and
// answers a different question.
func TestReportCarriesFrameworkAndFormat(t *testing.T) {
	srv, got := recordingServer(t, `{"uuid":"x","results":[]}`)
	handleReport(cfg(srv), []string{"--framework", "SOC2", "--format", "oscal"})

	full := got.path + "?" + got.query
	if !strings.Contains(full, "SOC2") {
		t.Errorf("request %q does not name the framework", full)
	}
	if !strings.Contains(full, "oscal") {
		t.Errorf("request %q does not carry the format", full)
	}
}

// Search is how an operator answers "where is this CVE running". Dropping the
// filter returns everything, which reads as a much larger blast radius than
// the truth -- or, with a different filter dropped, a much smaller one.
func TestSearchCarriesItsFilters(t *testing.T) {
	srv, got := recordingServer(t, `[]`)
	handleSearch(cfg(srv), []string{"artifacts", "--name", "payments-api"})

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if !strings.Contains(got.query, "payments-api") {
		t.Errorf("query = %q, want it to carry the name filter", got.query)
	}
}

// Impact answers "which artifacts and environments does this CVE touch". The
// CVE has to be in the request or the answer is about nothing.
func TestImpactCarriesTheCVE(t *testing.T) {
	srv, got := recordingServer(t, `{"artifacts":[],"environments":[]}`)
	handleImpact(cfg(srv), []string{"--cve", "CVE-2026-12345"})

	if !strings.Contains(got.path+"?"+got.query, "CVE-2026-12345") {
		t.Errorf("request %q%q does not carry the CVE", got.path, got.query)
	}
}

// A VEX statement suppresses a finding, so it is a claim someone is accountable
// for. Its CVE and status both have to survive the trip.
func TestVEXCarriesCVEAndStatus(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"recorded"}`)
	handleVEX(cfg(srv), []string{"--cve", "CVE-2026-99999", "--status", "not_affected"})

	full := got.path + "?" + got.query + got.raw
	if !strings.Contains(full, "CVE-2026-99999") {
		t.Errorf("request does not carry the CVE: %q", full)
	}
	if !strings.Contains(full, "not_affected") {
		t.Errorf("request does not carry the status: %q", full)
	}
}

// Metrics has subcommands that hit different endpoints. Sending them all to the
// same place would answer the wrong question convincingly.
func TestMetricsSubcommandsHitDifferentEndpoints(t *testing.T) {
	srv1, got1 := recordingServer(t, `{}`)
	handleMetrics(cfg(srv1), []string{})

	srv2, got2 := recordingServer(t, `{}`)
	handleMetrics(cfg(srv2), []string{"deployment-frequency"})

	if got1.path == got2.path {
		t.Errorf("metrics and deployment-frequency both hit %q; they are different questions", got1.path)
	}
	if !strings.Contains(got2.path, "deployment-frequency") {
		t.Errorf("deployment-frequency hit %q", got2.path)
	}
}

// A service account is a machine identity with a role. Creating one with the
// wrong role either breaks the pipeline or over-privileges it.
func TestServiceAccountCreateCarriesNameAndRole(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"sa-1"}`)
	handleServiceAccount(cfg(srv), []string{"create", "--name", "ci-pipeline", "--role", "Writer"})

	if got.body["name"] != "ci-pipeline" {
		t.Errorf("name = %v, want ci-pipeline", got.body["name"])
	}
	if got.body["role"] != "Writer" {
		t.Errorf("role = %v, want Writer -- the wrong role is either a broken pipeline or an over-privileged one", got.body["role"])
	}
}

// Flow subcommands scope by flow id. Losing it lists another flow's trails.
func TestFlowSubcommandsScopeByFlow(t *testing.T) {
	srv, got := recordingServer(t, `[]`)
	handleFlow(cfg(srv), []string{"trails", "--flow", "flow-7"})

	if !strings.Contains(got.path+"?"+got.query, "flow-7") {
		t.Errorf("request %q%q is not scoped to the flow", got.path, got.query)
	}
}
