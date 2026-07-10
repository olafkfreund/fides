package evidence

import "testing"

func TestParseJUnit(t *testing.T) {
	xml := []byte(`<testsuites>
	  <testsuite>
	    <testcase name="a" classname="pkg"/>
	    <testcase name="b" classname="pkg"><failure>boom</failure></testcase>
	    <testcase name="c" classname="pkg"><skipped/></testcase>
	  </testsuite>
	</testsuites>`)
	r, err := ParseJUnit(xml)
	if err != nil {
		t.Fatalf("ParseJUnit: %v", err)
	}
	if r.Compliant {
		t.Fatalf("a failing suite must not be compliant")
	}
	if r.Summary["total"] != 3 || r.Summary["passed"] != 1 || r.Summary["failed"] != 1 || r.Summary["skipped"] != 1 {
		t.Fatalf("summary wrong: %+v", r.Summary)
	}
	if len(r.Findings) != 1 || r.Findings[0] != "pkg.b" {
		t.Fatalf("findings wrong: %+v", r.Findings)
	}
}

func TestParseJUnitSingleSuiteAllPass(t *testing.T) {
	r, err := ParseJUnit([]byte(`<testsuite><testcase name="x"/><testcase name="y"/></testsuite>`))
	if err != nil || !r.Compliant || r.Summary["passed"] != 2 {
		t.Fatalf("expected compliant all-pass: %+v err=%v", r, err)
	}
}

func TestParseSnyk(t *testing.T) {
	clean, _ := ParseSnyk([]byte(`{"ok":true,"vulnerabilities":[]}`))
	if !clean.Compliant {
		t.Fatalf("no vulns should be compliant")
	}
	bad, _ := ParseSnyk([]byte(`{"ok":false,"vulnerabilities":[{"id":"SNYK-1","title":"RCE","severity":"high"},{"id":"SNYK-2","title":"x","severity":"low"}]}`))
	if bad.Compliant {
		t.Fatalf("a high vuln must fail")
	}
	if bad.Summary["high"] != 1 || bad.Summary["low"] != 1 || len(bad.Findings) != 1 {
		t.Fatalf("snyk summary wrong: %+v findings=%+v", bad.Summary, bad.Findings)
	}
}

func TestParseTrivy(t *testing.T) {
	r, _ := ParseTrivy([]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"CRITICAL"},{"VulnerabilityID":"CVE-2","Severity":"MEDIUM"}]}]}`))
	if r.Compliant {
		t.Fatalf("a critical must fail")
	}
	if r.Summary["critical"] != 1 || r.Summary["medium"] != 1 || r.Summary["total"] != 2 {
		t.Fatalf("trivy summary wrong: %+v", r.Summary)
	}
}

func TestParseSARIF(t *testing.T) {
	// One error, one warning, one note, plus a level-less result (defaults to warning).
	report := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "CodeQL"}},
			"results": [
				{"ruleId": "js/sql-injection", "level": "error", "message": {"text": "SQL injection"}},
				{"ruleId": "js/unused-var", "level": "warning", "message": {"text": "unused"}},
				{"ruleId": "js/style", "level": "note", "message": {"text": "style"}},
				{"ruleId": "js/no-level", "message": {"text": "defaults to warning"}}
			]
		}]
	}`)
	r, err := ParseSARIF(report)
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if r.Compliant {
		t.Fatalf("an error-level result must fail")
	}
	if r.Summary["total"] != 4 || r.Summary["error"] != 1 || r.Summary["warning"] != 2 || r.Summary["note"] != 1 {
		t.Fatalf("sarif summary wrong: %+v", r.Summary)
	}
	if len(r.Findings) != 1 || r.Findings[0] != "ERROR: js/sql-injection (SQL injection)" {
		t.Fatalf("sarif findings wrong: %+v", r.Findings)
	}
}

func TestParseSARIFClean(t *testing.T) {
	// Warnings and notes only, spanning multiple runs -> compliant.
	report := []byte(`{
		"runs": [
			{"tool": {"driver": {"name": "Semgrep"}}, "results": [{"ruleId": "a", "level": "warning", "message": {"text": "w"}}]},
			{"tool": {"driver": {"name": "Grype"}}, "results": [{"ruleId": "b", "level": "note", "message": {"text": "n"}}]}
		]
	}`)
	r, err := Parse("sarif", report)
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if !r.Compliant || r.Format != "sarif" {
		t.Fatalf("expected compliant sarif result: %+v", r)
	}
	if r.Summary["total"] != 2 || r.Summary["warning"] != 1 || r.Summary["note"] != 1 || len(r.Findings) != 0 {
		t.Fatalf("sarif summary/findings wrong: %+v findings=%+v", r.Summary, r.Findings)
	}
}

func TestParseSARIFEmptyAndInvalid(t *testing.T) {
	// No runs/results -> compliant with zero counts.
	r, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if !r.Compliant || r.Summary["total"] != 0 {
		t.Fatalf("empty sarif must be compliant with total 0: %+v", r)
	}
	if _, err := Parse("sarif", []byte("not json")); err == nil {
		t.Fatalf("invalid json must error")
	}
}

func TestParseSARIFErrorNoRuleID(t *testing.T) {
	report := []byte(`{"runs":[{"results":[{"level":"error","message":{}}]}]}`)
	r, err := ParseSARIF(report)
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if r.Compliant || len(r.Findings) != 1 || r.Findings[0] != "ERROR: (no rule id)" {
		t.Fatalf("expected one ruleless error finding: %+v", r.Findings)
	}
}

func TestParseSBOMCycloneDX(t *testing.T) {
	doc := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
			{"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"}
		]
	}`)
	r, err := ParseSBOM(doc)
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if r.Format != "cyclonedx" || !r.Compliant {
		t.Fatalf("expected compliant cyclonedx result: %+v", r)
	}
	if r.Summary["components"] != 2 || len(r.Components) != 2 {
		t.Fatalf("expected 2 components: %+v", r)
	}
	// sorted by name: axios, lodash
	if r.Components[0].Name != "axios" || r.Components[1].Name != "lodash" {
		t.Fatalf("components not sorted: %+v", r.Components)
	}
	if r.Components[1].PURL != "pkg:npm/lodash@4.17.21" || len(r.Components[1].Licenses) != 1 || r.Components[1].Licenses[0] != "MIT" {
		t.Fatalf("lodash component wrong: %+v", r.Components[1])
	}
}

func TestParseSBOMSPDX(t *testing.T) {
	doc := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "lodash",
				"versionInfo": "4.17.21",
				"licenseConcluded": "MIT",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}]
			},
			{"name": "unlicensed-pkg", "versionInfo": "1.0.0", "licenseConcluded": "NOASSERTION"}
		]
	}`)
	r, err := ParseSBOM(doc)
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if r.Format != "spdx" || !r.Compliant || len(r.Components) != 2 {
		t.Fatalf("expected compliant spdx result with 2 components: %+v", r)
	}
	// sorted by name: lodash, unlicensed-pkg
	if r.Components[0].Name != "lodash" || r.Components[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("lodash component wrong: %+v", r.Components[0])
	}
	if len(r.Components[1].Licenses) != 0 {
		t.Fatalf("NOASSERTION license should not be recorded: %+v", r.Components[1])
	}
}

func TestParseSBOMUnrecognized(t *testing.T) {
	if _, err := ParseSBOM([]byte(`{"foo":"bar"}`)); err == nil {
		t.Fatalf("unrecognized sbom format must error")
	}
	if _, err := ParseSBOM([]byte(`not json`)); err == nil {
		t.Fatalf("invalid json must error")
	}
}

func TestParseDispatchAndErrors(t *testing.T) {
	if _, err := Parse("unknown", nil); err == nil {
		t.Fatalf("unknown format must error")
	}
	if _, err := Parse("snyk", []byte("not json")); err == nil {
		t.Fatalf("invalid json must error")
	}
	if _, err := Parse("junit", []byte("<bad")); err == nil {
		t.Fatalf("invalid xml must error")
	}
}

func TestParseSLSACompliant(t *testing.T) {
	stmt := `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "subject": [{"name": "app", "digest": {"sha256": "abc123"}}],
	  "predicate": {
	    "buildDefinition": {
	      "buildType": "https://github.com/actions/runner/github-hosted",
	      "externalParameters": {"workflow": "build.yml"}
	    },
	    "runDetails": {
	      "builder": {"id": "https://github.com/actions/runner"},
	      "metadata": {"invocationId": "1234", "startedOn": "2026-07-01T00:00:00Z"}
	    }
	  }
	}`
	r, err := Parse("slsa", []byte(stmt))
	if err != nil {
		t.Fatalf("ParseSLSA: %v", err)
	}
	if !r.Compliant {
		t.Fatalf("expected compliant provenance, findings=%+v", r.Findings)
	}
	if r.Format != "slsa" {
		t.Fatalf("format wrong: %+v", r.Format)
	}
	if r.Summary["builder_id"] != "https://github.com/actions/runner" {
		t.Fatalf("summary builder_id wrong: %+v", r.Summary)
	}
	if r.Summary["build_type"] != "https://github.com/actions/runner/github-hosted" {
		t.Fatalf("summary build_type wrong: %+v", r.Summary)
	}
	if r.Summary["subjects"] != 1 {
		t.Fatalf("summary subjects wrong: %+v", r.Summary)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings: %+v", r.Findings)
	}
}

func TestParseSLSANonCompliantMissingFields(t *testing.T) {
	// Wrong predicateType, no subject, no builder.id.
	stmt := `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "predicateType": "https://example.com/not-slsa",
	  "predicate": {
	    "buildDefinition": {"buildType": ""},
	    "runDetails": {"builder": {"id": ""}}
	  }
	}`
	r, err := ParseSLSA([]byte(stmt))
	if err != nil {
		t.Fatalf("ParseSLSA: %v", err)
	}
	if r.Compliant {
		t.Fatalf("malformed provenance must not be compliant: %+v", r)
	}
	wantFindings := []string{
		`missing predicate.buildDefinition.buildType`,
		`missing predicate.runDetails.builder.id`,
		`missing subject`,
		`unexpected predicateType "https://example.com/not-slsa" (want "https://slsa.dev/provenance/v1")`,
	}
	if len(r.Findings) != len(wantFindings) {
		t.Fatalf("findings wrong: got %+v want %+v", r.Findings, wantFindings)
	}
	for i, f := range wantFindings {
		if r.Findings[i] != f {
			t.Fatalf("finding %d wrong: got %q want %q", i, r.Findings[i], f)
		}
	}
}

func TestParseSLSAMissingRunDetailsAndBuildDefinition(t *testing.T) {
	r, err := ParseSLSA([]byte(`{"predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"x"}],"predicate":{}}`))
	if err != nil {
		t.Fatalf("ParseSLSA: %v", err)
	}
	if r.Compliant {
		t.Fatalf("missing buildDefinition/runDetails must not be compliant: %+v", r)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", r.Findings)
	}
}

func TestParseSLSAInvalidJSON(t *testing.T) {
	if _, err := Parse("slsa", []byte("not json")); err == nil {
		t.Fatalf("invalid json must error")
	}
}
