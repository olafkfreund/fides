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
