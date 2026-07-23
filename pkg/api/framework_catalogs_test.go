package api

import "testing"

// The supply-chain provenance evidence types (cosign-verification and
// slsa-provenance) must be recognized in the framework catalogs so that a trail
// carrying that evidence contributes to control coverage and lowers the
// change-gate risk score (issue #222). This guards the exact type_name strings
// the recorders emit (`fides verify-image` -> cosign-verification;
// `fides attest slsa|fetch` -> slsa-provenance).
func TestFrameworkCatalogsRecognizeSupplyChainEvidence(t *testing.T) {
	// A dedicated SLSA supply-chain framework exists.
	slsa, ok := frameworkCatalogs["SLSA"]
	if !ok {
		t.Fatal("SLSA framework catalog is missing")
	}

	// Collect every required type across the SLSA catalog and every catalog.
	want := map[string]bool{"slsa-provenance": false, "cosign-verification": false, "sbom-cyclonedx": false}
	for _, c := range slsa {
		for _, tn := range c.RequiredTypes {
			if _, tracked := want[tn]; tracked {
				want[tn] = true
			}
		}
	}
	for tn, seen := range want {
		if !seen {
			t.Errorf("SLSA framework does not require expected supply-chain type %q", tn)
		}
	}

	// The supply-chain types must also be reachable from a mainstream framework
	// so importing e.g. NIST-800-53 requires provenance + signature evidence.
	requireTypeInFramework(t, "NIST-800-53", "slsa-provenance")
	requireTypeInFramework(t, "NIST-800-53", "cosign-verification")
	requireTypeInFramework(t, "SOC2", "slsa-provenance")
}

// The EU Cyber Resilience Act catalog must exist and require the CRA
// load-bearing evidence: a machine-readable SBOM and vulnerability handling,
// plus artifact integrity. Guards the exact evidence type_name strings so an
// org importing CRA gets reportable control coverage (#293).
func TestCRAFrameworkCatalog(t *testing.T) {
	if _, ok := frameworkCatalogs["CRA"]; !ok {
		t.Fatal("CRA framework catalog is missing")
	}
	requireTypeInFramework(t, "CRA", "sbom-cyclonedx")
	requireTypeInFramework(t, "CRA", "trivy")
	requireTypeInFramework(t, "CRA", "cosign-verification")
}

func requireTypeInFramework(t *testing.T, framework, typeName string) {
	t.Helper()
	for _, c := range frameworkCatalogs[framework] {
		for _, tn := range c.RequiredTypes {
			if tn == typeName {
				return
			}
		}
	}
	t.Errorf("framework %q does not require type %q in any control", framework, typeName)
}
