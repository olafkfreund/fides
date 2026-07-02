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
