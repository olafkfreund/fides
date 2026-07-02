package servicenow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fides/pkg/ledger"
)

func TestQueryChangeRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/now/table/change_request" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("sysparm_query") != "number=CHG0030192" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"result":[{"number":"CHG0030192","state":"-1","approval":"approved","risk":"low","on_hold":"false"}]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	cr, found, err := QueryChangeRequest(context.Background(), c, "number=CHG0030192")
	if err != nil || !found {
		t.Fatalf("expected a change request, found=%v err=%v", found, err)
	}
	if cr["number"] != "CHG0030192" {
		t.Fatalf("wrong CR: %+v", cr)
	}
}

func TestQueryChangeRequestNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, AuthBasic, srv.Client())
	_, found, err := QueryChangeRequest(context.Background(), c, "number=NOPE")
	if err != nil || found {
		t.Fatalf("expected not found, got found=%v err=%v", found, err)
	}
}

func TestNormalizeChange(t *testing.T) {
	cr := map[string]any{
		"number":   "CHG0030192",
		"state":    "-1", // implement
		"approval": "approved",
		"risk":     "moderate",
		"on_hold":  "false",
	}
	n := NormalizeChange(cr)
	if n["state"] != "implement" {
		t.Errorf("state should map to label 'implement', got %v", n["state"])
	}
	if n["on_hold"] != false {
		t.Errorf("on_hold should be a bool false, got %v (%T)", n["on_hold"], n["on_hold"])
	}
	if n["approval"] != "approved" {
		t.Errorf("approval = %v", n["approval"])
	}

	// A display-value state passes through unchanged.
	if NormalizeChange(map[string]any{"state": "Implement"})["state"] != "Implement" {
		t.Errorf("display-value state should pass through")
	}
}

// baseGate is a minimal change-gate verdict, as produced by the change-gate
// evaluator, without an evidence bundle attached.
func baseGate() map[string]any {
	return map[string]any{
		"recommendation": "approve",
		"risk_score":     12,
		"risk_level":     "low",
		"summary":        "All controls satisfied.",
		"passed":         []string{"SOC2-CC7.1"},
	}
}

func TestBuildChangeGateNoteWithoutEvidenceBundle(t *testing.T) {
	note := BuildChangeGateNote(baseGate())
	if !strings.Contains(note, "recommendation: approve (risk 12 / low)") {
		t.Errorf("note missing verdict summary: %s", note)
	}
	if strings.Contains(note, "Evidence bundle:") {
		t.Errorf("note should not render an evidence bundle section when none is attached: %s", note)
	}
}

func TestBuildChangeGateNoteWithEvidenceBundle(t *testing.T) {
	gate := baseGate()
	gate["evidence_bundle"] = map[string]any{
		"chain": ledger.Verdict{Valid: true, Count: 3, BrokenAt: -1},
		"artifacts": []map[string]any{
			{"name": "api-server", "sha256": "abc123", "type": "docker"},
		},
		"attestation_types": map[string]map[string]int{
			"snyk-scan":  {"total": 2, "compliant": 2, "non_compliant": 0},
			"unit-tests": {"total": 1, "compliant": 1, "non_compliant": 0},
		},
	}

	note := BuildChangeGateNote(gate)
	for _, want := range []string{
		"Evidence bundle:",
		"Chain: INTACT (3 attestations verified)",
		"api-server: sha256:abc123",
		"snyk-scan: 2 compliant / 2 total",
		"unit-tests: 1 compliant / 1 total",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q; got:\n%s", want, note)
		}
	}
}

func TestBuildChangeGateNoteWithTamperedChain(t *testing.T) {
	gate := baseGate()
	gate["evidence_bundle"] = map[string]any{
		"chain": ledger.Verdict{Valid: false, Count: 3, BrokenAt: 1, Reason: "content_hash does not match recomputed hash (tampering)"},
	}
	note := BuildChangeGateNote(gate)
	if !strings.Contains(note, "Chain: TAMPERED") {
		t.Errorf("note should flag a tampered chain: %s", note)
	}
	if !strings.Contains(note, "broken at index 1") {
		t.Errorf("note should report the break point: %s", note)
	}
}

// TestChangeGateWriteBackIncludesEvidence exercises the full write-back path
// against a mock ServiceNow instance: the change_request PATCH must carry the
// risk score/level and the signed evidence bundle in work_notes.
func TestChangeGateWriteBackIncludesEvidence(t *testing.T) {
	var gotFields map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/now/table/change_request/sys123" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotFields); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Write([]byte(`{"result":{"sys_id":"sys123"}}`))
	}))
	defer srv.Close()

	gate := baseGate()
	gate["risk_score"] = 55
	gate["risk_level"] = "high"
	gate["evidence_bundle"] = map[string]any{
		"chain": ledger.Verdict{Valid: true, Count: 5, BrokenAt: -1},
		"artifacts": []map[string]any{
			{"name": "payments-api", "sha256": "deadbeef", "type": "docker"},
		},
		"attestation_types": map[string]map[string]int{
			"sbom": {"total": 1, "compliant": 1, "non_compliant": 0},
		},
	}

	c := testClient(srv.URL, AuthBasic, srv.Client())
	note := BuildChangeGateNote(gate)
	if _, err := c.UpdateRecord(context.Background(), "change_request", "sys123", map[string]any{
		"work_notes": note,
		"risk":       "2", // High
	}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	workNotes, _ := gotFields["work_notes"].(string)
	if !strings.Contains(workNotes, "risk 55 / high") {
		t.Errorf("work_notes missing risk score/level: %s", workNotes)
	}
	if !strings.Contains(workNotes, "Chain: INTACT (5 attestations verified)") {
		t.Errorf("work_notes missing chain verdict: %s", workNotes)
	}
	if !strings.Contains(workNotes, "payments-api: sha256:deadbeef") {
		t.Errorf("work_notes missing artifact digest: %s", workNotes)
	}
	if !strings.Contains(workNotes, "sbom: 1 compliant / 1 total") {
		t.Errorf("work_notes missing attestation type counts: %s", workNotes)
	}
	if gotFields["risk"] != "2" {
		t.Errorf("risk field = %v, want 2 (High)", gotFields["risk"])
	}
}
