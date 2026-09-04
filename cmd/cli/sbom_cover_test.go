package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fides/pkg/evidence"
)

const sbomCoverCycloneDX = `{
  "bomFormat": "CycloneDX",
  "components": [
    {"name": "b-lib", "version": "2.0", "purl": "pkg:golang/b-lib@2.0"},
    {"name": "a-lib", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]}
  ]
}`

func sbomCoverWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func sbomCoverCaptureStdout(t *testing.T, fn func()) string {
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

// parseSBOMFile must read the file and return the components.
func TestParseSBOMFile(t *testing.T) {
	dir := t.TempDir()
	path := sbomCoverWrite(t, dir, "bom.json", sbomCoverCycloneDX)

	got := parseSBOMFile(path)

	if len(got) != 2 {
		t.Fatalf("components = %v, want 2", got)
	}
	byName := map[string]string{}
	for _, c := range got {
		byName[c.Name] = c.Version
	}
	if byName["a-lib"] != "1.0" || byName["b-lib"] != "2.0" {
		t.Errorf("components = %v, want a-lib@1.0 and b-lib@2.0", got)
	}
}

// printSBOMDiff must show counts and each line in the +/-/~ shape CI greps
// for.
func TestPrintSBOMDiffNonEmpty(t *testing.T) {
	oldC := []evidence.Component{
		{Name: "c", Version: "3.0"},
		{Name: "b", Version: "2.0"},
	}
	newC := []evidence.Component{
		{Name: "a", Version: "1.0"},
		{Name: "b", Version: "2.1"},
	}

	d := diffSBOM(oldC, newC)
	out := sbomCoverCaptureStdout(t, func() {
		printSBOMDiff("old.json", "new.json", d)
	})

	for _, want := range []string{
		"SBOM diff: old.json -> new.json",
		"+1 added  -1 removed  ~1 changed",
		"+ a@1.0",
		"- c@3.0",
		"~ b 2.0 -> 2.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output = %q, want it to contain %q", out, want)
		}
	}
}

// An identical diff must print the "no changes" line, not silently empty
// added/removed/changed sections.
func TestPrintSBOMDiffEmpty(t *testing.T) {
	out := sbomCoverCaptureStdout(t, func() {
		printSBOMDiff("old.json", "new.json", diffSBOM(nil, nil))
	})
	if !strings.Contains(out, "no component changes") {
		t.Errorf("output = %q, want the no-changes line", out)
	}
}

// handleSBOMDiff must parse both files and print the text report by default.
func TestHandleSBOMDiffText(t *testing.T) {
	dir := t.TempDir()
	oldPath := sbomCoverWrite(t, dir, "old.json", sbomCoverCycloneDX)
	newPath := sbomCoverWrite(t, dir, "new.json", sbomCoverCycloneDX)

	out := sbomCoverCaptureStdout(t, func() {
		handleSBOMDiff([]string{oldPath, newPath})
	})

	if !strings.Contains(out, "SBOM diff:") || !strings.Contains(out, "no component changes") {
		t.Errorf("output = %q, want a text diff report with no changes", out)
	}
}

// --json must be accepted in any position (the whole point of the manual
// flag parse: stdlib flag would reject it after the positionals) and must
// render valid JSON with the expected shape.
func TestHandleSBOMDiffJSONFlagAnyPosition(t *testing.T) {
	dir := t.TempDir()
	oldPath := sbomCoverWrite(t, dir, "old.json", sbomCoverCycloneDX)
	newBody := `{"bomFormat":"CycloneDX","components":[{"name":"a-lib","version":"1.0"},{"name":"b-lib","version":"2.0"},{"name":"new-lib","version":"9.0"}]}`
	newPath := sbomCoverWrite(t, dir, "new.json", newBody)

	out := sbomCoverCaptureStdout(t, func() {
		handleSBOMDiff([]string{oldPath, newPath, "--json"})
	})

	var got struct {
		Added []struct {
			Name string `json:"name"`
		} `json:"added"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if len(got.Added) != 1 || got.Added[0].Name != "new-lib" {
		t.Errorf("added = %+v, want [new-lib]", got.Added)
	}
}

// handleSBOM must route the "diff" subcommand to handleSBOMDiff.
func TestHandleSBOMDispatchesToDiff(t *testing.T) {
	dir := t.TempDir()
	path := sbomCoverWrite(t, dir, "bom.json", sbomCoverCycloneDX)

	out := sbomCoverCaptureStdout(t, func() {
		handleSBOM(CLIConfig{}, []string{"diff", path, path})
	})

	if !strings.Contains(out, "SBOM diff:") {
		t.Errorf("output = %q, want handleSBOM to have run the diff", out)
	}
}

// handleAttestSBOM's success path: it must parse the SBOM, record it against
// the server with the fixed sbom-cyclonedx type name, and report the
// component count.
func TestHandleAttestSBOM(t *testing.T) {
	srv, got := recordingServer(t, `{"id":"att-1"}`)
	dir := t.TempDir()
	path := sbomCoverWrite(t, dir, "bom.json", sbomCoverCycloneDX)

	out := sbomCoverCaptureStdout(t, func() {
		handleAttestSBOM(cfg(srv), []string{
			"--file", path, "--artifact-sha", strings.Repeat("a", 64),
		})
	})

	if got.hits != 1 {
		t.Fatalf("expected exactly one request, got %d", got.hits)
	}
	// The request is multipart/form-data, not JSON, so assert on the raw body
	// rather than the recorder's (JSON-only) parsed field.
	if !strings.Contains(got.raw, `name="type_name"`) || !strings.Contains(got.raw, "sbom-cyclonedx") {
		t.Errorf("request body = %q, want a type_name field of sbom-cyclonedx", got.raw)
	}
	if !strings.Contains(out, "format=cyclonedx") || !strings.Contains(out, "2 components") {
		t.Errorf("output = %q, want the format and component count reported", out)
	}
}
