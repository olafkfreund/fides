package main

import "testing"

// evidenceTypeName canonicalizes SLSA to the "slsa-provenance" type_name that
// framework controls require, while leaving the other formats untouched. This
// is what makes `fides attest slsa` land under the same type as the
// platform-native `fides attest fetch` path.
func TestEvidenceTypeName(t *testing.T) {
	cases := map[string]string{
		"slsa":  "slsa-provenance",
		"junit": "junit",
		"snyk":  "snyk",
		"trivy": "trivy",
	}
	for in, want := range cases {
		if got := evidenceTypeName(in); got != want {
			t.Errorf("evidenceTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}
