package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vulnCoverWriteReport writes a minimal trivy-shaped JSON report naming the
// given CVEs as CRITICAL findings.
func vulnCoverWriteReport(t *testing.T, dir, name string, cves ...string) string {
	t.Helper()
	var vulns []string
	for _, c := range cves {
		vulns = append(vulns, `{"VulnerabilityID":"`+c+`","Severity":"CRITICAL"}`)
	}
	body := `{"Results":[{"Vulnerabilities":[` + strings.Join(vulns, ",") + `]}]}`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// vulnCoverCaptureStdout runs fn and returns everything it printed.
func vulnCoverCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	buf := make([]byte, 64<<10)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

// cvesFromReport must read a real report and pull only CRITICAL/HIGH CVE ids
// out of the findings, which is exactly what handleVulnDiff's gate depends on.
func TestCvesFromReport(t *testing.T) {
	dir := t.TempDir()
	path := vulnCoverWriteReport(t, dir, "r.json", "CVE-2021-44228", "CVE-2022-1234")

	got := cvesFromReport("trivy", path)

	if !got["CVE-2021-44228"] || !got["CVE-2022-1234"] || len(got) != 2 {
		t.Errorf("cvesFromReport = %v, want exactly the two CVEs", got)
	}
}

// handleVulnDiff without --fail-on-new must never exit even when new CVEs
// appear, and must print both the added and fixed sections.
func TestHandleVulnDiffPrintsAddedAndFixed(t *testing.T) {
	dir := t.TempDir()
	base := vulnCoverWriteReport(t, dir, "base.json", "CVE-2021-0001")
	cur := vulnCoverWriteReport(t, dir, "cur.json", "CVE-2022-9999")

	out := vulnCoverCaptureStdout(t, func() {
		handleVulnDiff([]string{base, cur})
	})

	if !strings.Contains(out, "+1 new") || !strings.Contains(out, "-1 fixed") {
		t.Errorf("output = %q, want counts for 1 new and 1 fixed", out)
	}
	if !strings.Contains(out, "CVE-2022-9999 (new)") {
		t.Errorf("output = %q, want the new CVE listed", out)
	}
	if !strings.Contains(out, "CVE-2021-0001 (fixed)") {
		t.Errorf("output = %q, want the fixed CVE listed", out)
	}
}

// No CVE delta must print the "no change" line, not empty added/fixed
// sections that look like the diff silently did nothing.
func TestHandleVulnDiffNoChange(t *testing.T) {
	dir := t.TempDir()
	path := vulnCoverWriteReport(t, dir, "same.json", "CVE-2021-0001")

	out := vulnCoverCaptureStdout(t, func() {
		handleVulnDiff([]string{path, path})
	})

	if !strings.Contains(out, "no change in CVE set") {
		t.Errorf("output = %q, want the no-change line", out)
	}
}

// --fail-on-new must not exit when nothing new was introduced -- only an
// actual new CVE may trigger the exit(2) gate, which this test cannot safely
// exercise since it would kill the test binary.
func TestHandleVulnDiffFailOnNewWithoutNewCVEsDoesNotExit(t *testing.T) {
	dir := t.TempDir()
	base := vulnCoverWriteReport(t, dir, "base.json", "CVE-2021-0001")
	cur := vulnCoverWriteReport(t, dir, "cur.json") // strict subset: nothing new

	out := vulnCoverCaptureStdout(t, func() {
		handleVulnDiff([]string{"--fail-on-new", "--format", "trivy", base, cur})
	})

	if !strings.Contains(out, "-1 fixed") {
		t.Errorf("output = %q, want the fixed CVE counted", out)
	}
	if strings.Contains(out, "gate failed") {
		t.Errorf("output = %q, must not report a gate failure when nothing new was introduced", out)
	}
}

// The `fides vuln diff` subcommand must route to handleVulnDiff.
func TestHandleVulnDispatchesToDiff(t *testing.T) {
	dir := t.TempDir()
	path := vulnCoverWriteReport(t, dir, "same.json", "CVE-2021-0001")

	out := vulnCoverCaptureStdout(t, func() {
		handleVuln(CLIConfig{}, []string{"diff", path, path})
	})

	if !strings.Contains(out, "Vuln diff") {
		t.Errorf("output = %q, want handleVuln to have run the diff", out)
	}
}
