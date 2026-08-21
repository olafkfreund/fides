package evidence

import (
	"testing"
)

// Every function here parses a file produced by somebody else's scanner and
// handed to Fides by a pipeline. That input is untrusted in the way that
// matters: it is not attacker-chosen in the usual sense, but it is arbitrary,
// it changes whenever a scanner is upgraded, and a panic while parsing it takes
// down the server that every pipeline in the organisation calls to get a
// release verdict. A malformed SBOM should be a rejected attestation, never an
// outage.
//
// These assert one property, which is the only one that always holds: parsing
// returns or errors, and never panics. Correctness of the parse is covered by
// the table tests in evidence_test.go; this is about what happens off the
// happy path.

// fuzzParser runs one parser over the corpus and fails only on a panic.
// Errors are the expected outcome for most inputs and are not interesting.
func fuzzParser(f *testing.F, seeds []string, parse func([]byte) (Result, error)) {
	f.Helper()
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// A panic here fails the test with the input that caused it, which go
		// test writes into testdata/ as a permanent regression case.
		_, _ = parse(data)
	})
}

func FuzzParseJUnit(f *testing.F) {
	fuzzParser(f, []string{
		`<testsuite tests="3" failures="0" errors="0"></testsuite>`,
		`<testsuites><testsuite tests="1" failures="1"><testcase><failure/></testcase></testsuite></testsuites>`,
		`<testsuite tests="-1" failures="99999999999999999999">`,
		`<?xml version="1.0"?><testsuite`,
		``,
	}, ParseJUnit)
}

func FuzzParseTrivy(f *testing.F) {
	fuzzParser(f, []string{
		`{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH"}]}]}`,
		`{"Results":null}`,
		`{"Results":[{"Vulnerabilities":null}]}`,
		`{"Results":[]}`,
		`{`,
		``,
	}, ParseTrivy)
}

func FuzzParseSnyk(f *testing.F) {
	fuzzParser(f, []string{
		`{"vulnerabilities":[{"id":"SNYK-1","severity":"critical"}]}`,
		`{"vulnerabilities":null}`,
		`{"vulnerabilities":[{}]}`,
		`[]`,
		``,
	}, ParseSnyk)
}

func FuzzParseSARIF(f *testing.F) {
	fuzzParser(f, []string{
		`{"runs":[{"results":[{"ruleId":"r1","level":"error"}]}]}`,
		`{"runs":[{"results":null}]}`,
		`{"runs":null}`,
		`{"runs":[{}]}`,
		``,
	}, ParseSARIF)
}

// The one most worth fuzzing: SBOMs are the largest and most structurally
// varied documents Fides ingests, and there are three formats behind this one
// entry point.
func FuzzParseSBOM(f *testing.F) {
	fuzzParser(f, []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"openssl","version":"3.0.1"}]}`,
		`{"bomFormat":"CycloneDX","components":null}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"openssl"}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":null}`,
		`{"artifacts":[{"name":"syft-style"}]}`,
		`{"components":[{"licenses":[{"license":{"id":"MIT"}}]}]}`,
		`{}`,
		``,
	}, ParseSBOM)
}

func FuzzParseSLSA(f *testing.F) {
	fuzzParser(f, []string{
		`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"a","digest":{"sha256":"abc"}}]}`,
		`{"subject":null}`,
		`{"subject":[{"digest":null}]}`,
		`{"predicate":{"builder":{"id":"x"}}}`,
		``,
	}, ParseSLSA)
}

// Parse dispatches on a format string that also comes from the caller, so the
// pair is worth exploring together: an unknown format must be an error, not a
// nil-map dereference somewhere downstream.
func FuzzParseDispatch(f *testing.F) {
	for _, fm := range []string{"junit", "trivy", "snyk", "sarif", "sbom", "slsa", "", "SBOM", "../etc/passwd"} {
		f.Add(fm, []byte(`{}`))
	}
	f.Fuzz(func(t *testing.T, format string, data []byte) {
		_, _ = Parse(format, data)
	})
}

// Provenance carries the digest a deployment gate compares against, so it is
// reached with attacker-influenced content more directly than the scanners.
func FuzzNormalizeProvenance(f *testing.F) {
	for _, s := range []string{
		`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"digest":{"sha256":"aa"}}]}`,
		`{"subject":[]}`,
		`{"subject":[{"digest":{}}]}`,
		`{}`,
		``,
	} {
		f.Add([]byte(s), "aa")
	}
	f.Fuzz(func(t *testing.T, statement []byte, expected string) {
		_, _ = NormalizeProvenance(statement, expected)
	})
}

// Commit messages are written by whoever opened the pull request.
func FuzzParseAuthorship(f *testing.F) {
	for _, s := range []string{
		"fix: a thing\n\nCo-Authored-By: Someone <a@b.c>",
		"Co-Authored-By:",
		"Generated with Claude",
		"\x00\xff",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		_ = ParseAuthorship(msg)
	})
}
