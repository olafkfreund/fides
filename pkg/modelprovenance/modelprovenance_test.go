package modelprovenance

import (
	"encoding/json"
	"testing"
	"time"
)

func TestValidRiskCategory(t *testing.T) {
	cases := map[string]bool{
		"high":         true,
		"HIGH":         true,
		" limited ":    true,
		"minimal":      true,
		"unacceptable": true,
		"medium":       false,
		"":             false,
	}
	for in, want := range cases {
		if got := ValidRiskCategory(in); got != want {
			t.Errorf("ValidRiskCategory(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTrailPayloadRequiresFlowAndVersion(t *testing.T) {
	if _, err := TrailPayload(ModelVersion{}); err == nil {
		t.Fatal("expected error for missing flow id and version")
	}
	if _, err := TrailPayload(ModelVersion{FlowID: "f1"}); err == nil {
		t.Fatal("expected error for missing version")
	}
	if _, err := TrailPayload(ModelVersion{Version: "v1"}); err == nil {
		t.Fatal("expected error for missing flow id")
	}
}

func TestTrailPayloadRejectsInvalidRiskCategory(t *testing.T) {
	_, err := TrailPayload(ModelVersion{FlowID: "f1", Version: "v1", RiskCategory: "extreme"})
	if err == nil {
		t.Fatal("expected error for invalid risk category")
	}
}

func TestTrailPayloadMapsEUAIActMetadataIntoTags(t *testing.T) {
	mv := ModelVersion{
		FlowID:          "flow-123",
		Version:         "v2.1.0",
		Repository:      "https://github.com/acme/fraud-model",
		Commit:          "abc123",
		Branch:          "main",
		Framework:       "pytorch",
		RiskCategory:    "High", // mixed case must normalize
		IntendedPurpose: "credit risk scoring",
		Tags:            map[string]string{"team": "risk-ml"},
	}
	payload, err := TrailPayload(mv)
	if err != nil {
		t.Fatalf("TrailPayload: %v", err)
	}

	if payload["flow_id"] != "flow-123" || payload["name"] != "v2.1.0" {
		t.Fatalf("unexpected identity fields: %+v", payload)
	}
	if payload["git_repository"] != mv.Repository || payload["git_commit"] != mv.Commit || payload["git_branch"] != mv.Branch {
		t.Fatalf("unexpected git fields: %+v", payload)
	}

	tags, ok := payload["tags"].(map[string]string)
	if !ok {
		t.Fatalf("tags is not a map[string]string: %#v", payload["tags"])
	}
	if tags["model_provenance"] != "true" {
		t.Errorf("expected model_provenance=true marker tag, got %+v", tags)
	}
	if tags["framework"] != "pytorch" {
		t.Errorf("framework tag wrong: %+v", tags)
	}
	if tags["risk_category"] != "high" {
		t.Errorf("risk_category should be normalized to lowercase, got %+v", tags)
	}
	if tags["intended_purpose"] != "credit risk scoring" {
		t.Errorf("intended_purpose tag wrong: %+v", tags)
	}
	if tags["team"] != "risk-ml" {
		t.Errorf("caller-supplied tags must be preserved: %+v", tags)
	}

	// The caller's map must not be mutated by TrailPayload.
	if _, present := mv.Tags["model_provenance"]; present {
		t.Errorf("TrailPayload must not mutate the caller's Tags map")
	}
}

func TestTrailPayloadOptionalFieldsOmittedFromTags(t *testing.T) {
	payload, err := TrailPayload(ModelVersion{FlowID: "f1", Version: "v1"})
	if err != nil {
		t.Fatalf("TrailPayload: %v", err)
	}
	tags := payload["tags"].(map[string]string)
	if _, present := tags["framework"]; present {
		t.Errorf("framework tag should be absent when not provided: %+v", tags)
	}
	if _, present := tags["risk_category"]; present {
		t.Errorf("risk_category tag should be absent when not provided: %+v", tags)
	}
	if tags["model_provenance"] != "true" {
		t.Errorf("model_provenance marker tag must always be set: %+v", tags)
	}
}

func TestEvidencePayloadRequiresKind(t *testing.T) {
	if _, err := EvidencePayload(Evidence{}); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

func TestEvidencePayloadRoundTrips(t *testing.T) {
	raw, err := EvidencePayload(Evidence{
		Kind:      KindEvaluation,
		Compliant: true,
		Summary:   map[string]any{"accuracy": 0.97},
		Findings:  []string{"none"},
		Metadata:  map[string]any{"dataset": "eval-2026-06"},
	})
	if err != nil {
		t.Fatalf("EvidencePayload: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if doc["kind"] != KindEvaluation {
		t.Errorf("kind wrong: %+v", doc)
	}
	if doc["compliant"] != true {
		t.Errorf("compliant wrong: %+v", doc)
	}
	if _, ok := doc["recorded_at"].(string); !ok {
		t.Errorf("recorded_at missing or not a string: %+v", doc)
	}
	summary, ok := doc["summary"].(map[string]any)
	if !ok || summary["accuracy"] != 0.97 {
		t.Errorf("summary not preserved: %+v", doc["summary"])
	}
}

func TestInferenceLogPayloadRequiresInputHashAndDecision(t *testing.T) {
	if _, err := InferenceLogPayload(InferenceEvent{}); err == nil {
		t.Fatal("expected error for missing input hash and decision")
	}
	if _, err := InferenceLogPayload(InferenceEvent{InputHash: "abc"}); err == nil {
		t.Fatal("expected error for missing decision")
	}
	if _, err := InferenceLogPayload(InferenceEvent{Decision: "approve"}); err == nil {
		t.Fatal("expected error for missing input hash")
	}
}

func TestInferenceLogPayloadRejectsOutOfRangeConfidence(t *testing.T) {
	tooHigh := 1.5
	if _, err := InferenceLogPayload(InferenceEvent{InputHash: "h", Decision: "d", Confidence: &tooHigh}); err == nil {
		t.Fatal("expected error for confidence > 1")
	}
	negative := -0.1
	if _, err := InferenceLogPayload(InferenceEvent{InputHash: "h", Decision: "d", Confidence: &negative}); err == nil {
		t.Fatal("expected error for negative confidence")
	}
}

func TestInferenceLogPayloadRoundTrips(t *testing.T) {
	conf := 0.83
	ts := time.Date(2026, 7, 2, 10, 30, 0, 0, time.UTC)
	raw, err := InferenceLogPayload(InferenceEvent{
		InputHash:  "in-hash",
		OutputHash: "out-hash",
		Decision:   "decline",
		Confidence: &conf,
		Actor:      "reviewer@acme.com",
		Metadata:   map[string]any{"model_endpoint": "v2"},
		Timestamp:  ts,
	})
	if err != nil {
		t.Fatalf("InferenceLogPayload: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if doc["input_hash"] != "in-hash" || doc["output_hash"] != "out-hash" || doc["decision"] != "decline" {
		t.Errorf("core fields wrong: %+v", doc)
	}
	if doc["confidence"] != 0.83 {
		t.Errorf("confidence wrong: %+v", doc["confidence"])
	}
	if doc["actor"] != "reviewer@acme.com" {
		t.Errorf("actor wrong: %+v", doc["actor"])
	}
	if doc["logged_at"] != "2026-07-02T10:30:00Z" {
		t.Errorf("logged_at wrong: %+v", doc["logged_at"])
	}
}

func TestInferenceLogPayloadDefaultsTimestamp(t *testing.T) {
	before := time.Now().UTC()
	raw, err := InferenceLogPayload(InferenceEvent{InputHash: "h", Decision: "d"})
	if err != nil {
		t.Fatalf("InferenceLogPayload: %v", err)
	}
	var doc map[string]any
	json.Unmarshal([]byte(raw), &doc)
	loggedAt, err := time.Parse(time.RFC3339, doc["logged_at"].(string))
	if err != nil {
		t.Fatalf("logged_at not a valid RFC3339 timestamp: %v", err)
	}
	if loggedAt.Before(before.Add(-time.Second)) {
		t.Errorf("logged_at %v should default to ~now (after %v)", loggedAt, before)
	}
}
