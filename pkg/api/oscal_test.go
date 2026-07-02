package api

import (
	"encoding/json"
	"testing"
)

func TestBuildOSCALAssessmentResults_ValidJSONShape(t *testing.T) {
	controls := []reportControl{
		{
			Key:               "SOC2-CC6.1",
			Name:              "Secrets are not committed",
			RequiredTypes:     []string{"secret-scan"},
			MissingTypes:      nil,
			EvidenceSatisfied: true,
			EnforcedIn:        []string{"prod"},
			Coverage:          1.0,
		},
		{
			Key:               "SOC2-CC7.1",
			Name:              "Artifacts pass vulnerability scanning",
			RequiredTypes:     []string{"trivy", "snyk"},
			MissingTypes:      []string{"snyk"},
			EvidenceSatisfied: false,
			EnforcedIn:        nil,
			Coverage:          0,
		},
	}

	doc := buildOSCALAssessmentResults("SOC2", controls)

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal OSCAL document: %v", err)
	}

	// Round-trip through a generic map to assert the expected OSCAL
	// assessment-results top-level shape without coupling the test to the
	// exact Go struct layout.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("OSCAL output is not valid JSON: %v", err)
	}

	ar, ok := generic["assessment-results"].(map[string]any)
	if !ok {
		t.Fatalf("missing top-level \"assessment-results\" key: %s", raw)
	}
	for _, key := range []string{"uuid", "metadata", "results"} {
		if _, ok := ar[key]; !ok {
			t.Fatalf("assessment-results missing %q: %s", key, raw)
		}
	}

	metadata, ok := ar["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not an object: %s", raw)
	}
	if metadata["title"] != "Fides Assessment Results: SOC2" {
		t.Errorf("unexpected metadata.title: %v", metadata["title"])
	}
	if metadata["oscal-version"] != "1.1.2" {
		t.Errorf("unexpected metadata.oscal-version: %v", metadata["oscal-version"])
	}

	results, ok := ar["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected exactly one result, got: %v", ar["results"])
	}
	result, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %v", results[0])
	}
	for _, key := range []string{"uuid", "title", "reviewed-controls", "findings"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("result missing %q: %s", key, raw)
		}
	}

	findings, ok := result["findings"].([]any)
	if !ok || len(findings) != len(controls) {
		t.Fatalf("expected %d findings, got: %v", len(controls), result["findings"])
	}

	// The satisfied control should carry a "satisfied" finding status; the
	// unsatisfied one "not-satisfied".
	gotStates := map[string]string{}
	for _, f := range findings {
		finding, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("finding is not an object: %v", f)
		}
		target, ok := finding["target"].(map[string]any)
		if !ok {
			t.Fatalf("finding.target is not an object: %v", finding["target"])
		}
		status, ok := target["status"].(map[string]any)
		if !ok {
			t.Fatalf("finding.target.status is not an object: %v", target["status"])
		}
		targetID, _ := target["target-id"].(string)
		state, _ := status["state"].(string)
		gotStates[targetID] = state
	}
	if gotStates["SOC2-CC6.1"] != "satisfied" {
		t.Errorf("expected SOC2-CC6.1 satisfied, got %q", gotStates["SOC2-CC6.1"])
	}
	if gotStates["SOC2-CC7.1"] != "not-satisfied" {
		t.Errorf("expected SOC2-CC7.1 not-satisfied, got %q", gotStates["SOC2-CC7.1"])
	}

	// One observation per distinct compliant evidence type: "secret-scan"
	// (SOC2-CC6.1's sole requirement) and "trivy" (present/compliant for
	// SOC2-CC7.1 even though that control is overall unsatisfied because its
	// other requirement, "snyk", is missing).
	observations, ok := result["observations"].([]any)
	if !ok || len(observations) != 2 {
		t.Fatalf("expected exactly 2 observations, got: %v", result["observations"])
	}
}
