package evidence

import "testing"

const provTestSHA = "76c34666f719ef14bd2b124a7db51e9c05e4db2e12a84800296d559064eebe2c"

func TestNormalizeProvenanceSLSAv1Compliant(t *testing.T) {
	stmt := []byte(`{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "app", "digest": {"sha256": "` + provTestSHA + `"}}],
		"predicate": {
			"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"},
			"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}
		}
	}`)
	r, err := NormalizeProvenance(stmt, provTestSHA)
	if err != nil {
		t.Fatalf("NormalizeProvenance: %v", err)
	}
	if !r.Compliant {
		t.Fatalf("expected compliant, findings=%v summary=%+v", r.Findings, r.Summary)
	}
	if r.Summary["builder_id"] != "https://github.com/actions/runner" {
		t.Errorf("builder_id = %v", r.Summary["builder_id"])
	}
	if r.Summary["digest_match"] != true {
		t.Errorf("digest_match = %v", r.Summary["digest_match"])
	}
}

func TestNormalizeProvenanceSLSAv02Compliant(t *testing.T) {
	stmt := []byte(`{
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"subject": [{"name": "app", "digest": {"sha256": "` + provTestSHA + `"}}],
		"predicate": {
			"buildType": "https://example.com/build",
			"builder": {"id": "https://example.com/builder"}
		}
	}`)
	r, err := NormalizeProvenance(stmt, provTestSHA)
	if err != nil {
		t.Fatalf("NormalizeProvenance: %v", err)
	}
	if !r.Compliant {
		t.Fatalf("expected compliant, findings=%v", r.Findings)
	}
	if r.Summary["build_type"] != "https://example.com/build" {
		t.Errorf("build_type = %v", r.Summary["build_type"])
	}
}

func TestNormalizeProvenanceDigestMismatch(t *testing.T) {
	stmt := []byte(`{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "app", "digest": {"sha256": "deadbeef"}}],
		"predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}}
	}`)
	r, err := NormalizeProvenance(stmt, provTestSHA)
	if err != nil {
		t.Fatalf("NormalizeProvenance: %v", err)
	}
	if r.Compliant {
		t.Fatalf("expected non-compliant due to digest mismatch")
	}
	if len(r.Findings) == 0 {
		t.Fatalf("expected a finding explaining the mismatch")
	}
}

func TestNormalizeProvenanceMissingBuilder(t *testing.T) {
	stmt := []byte(`{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "app", "digest": {"sha256": "` + provTestSHA + `"}}],
		"predicate": {}
	}`)
	r, err := NormalizeProvenance(stmt, provTestSHA)
	if err != nil {
		t.Fatalf("NormalizeProvenance: %v", err)
	}
	if r.Compliant {
		t.Fatalf("expected non-compliant due to missing builder id")
	}
}

func TestNormalizeProvenanceNoExpectedSHAStillChecksBuilder(t *testing.T) {
	stmt := []byte(`{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "app", "digest": {"sha256": "anything"}}],
		"predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}}
	}`)
	r, err := NormalizeProvenance(stmt, "")
	if err != nil {
		t.Fatalf("NormalizeProvenance: %v", err)
	}
	if !r.Compliant {
		t.Fatalf("expected compliant when no expected sha256 is given, findings=%v", r.Findings)
	}
}

func TestNormalizeProvenanceInvalidJSON(t *testing.T) {
	if _, err := NormalizeProvenance([]byte("not json"), provTestSHA); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNormalizeProvenanceMissingPredicateType(t *testing.T) {
	if _, err := NormalizeProvenance([]byte(`{"subject":[]}`), provTestSHA); err == nil {
		t.Fatal("expected error for missing predicateType")
	}
}
