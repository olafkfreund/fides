package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDriftDetected(t *testing.T) {
	tests := []struct {
		name string
		diff map[string]any
		want bool
	}{
		{
			name: "no changes",
			diff: map[string]any{
				"added":   []map[string]string{},
				"removed": []map[string]string{},
				"changed": []map[string]string{},
			},
			want: false,
		},
		{
			name: "service added",
			diff: map[string]any{
				"added":   []map[string]string{{"service": "checkout", "digest": "sha256:abc"}},
				"removed": []map[string]string{},
				"changed": []map[string]string{},
			},
			want: true,
		},
		{
			name: "service removed",
			diff: map[string]any{
				"added":   []map[string]string{},
				"removed": []map[string]string{{"service": "checkout", "digest": "sha256:abc"}},
				"changed": []map[string]string{},
			},
			want: true,
		},
		{
			name: "digest changed",
			diff: map[string]any{
				"added":   []map[string]string{},
				"removed": []map[string]string{},
				"changed": []map[string]string{{"service": "checkout", "from": "sha256:abc", "to": "sha256:def"}},
			},
			want: true,
		},
		{
			name: "missing keys treated as no drift",
			diff: map[string]any{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := driftDetected(tt.diff); got != tt.want {
				t.Errorf("driftDetected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestElevatedRiskField(t *testing.T) {
	tests := []struct {
		name    string
		current string
		want    string
	}{
		{name: "low escalates to high", current: "4", want: "2"},
		{name: "moderate escalates to high", current: "3", want: "2"},
		{name: "already high stays high", current: "2", want: "2"},
		{name: "unset escalates to high", current: "", want: "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elevatedRiskField(tt.current); got != tt.want {
				t.Errorf("elevatedRiskField(%q) = %q, want %q", tt.current, got, tt.want)
			}
		})
	}
}

func TestSnRiskLabel(t *testing.T) {
	tests := map[string]string{
		"2": "High",
		"3": "Moderate",
		"4": "Low",
		"":  "unset",
		"9": "9", // unknown codes pass through
	}
	for code, want := range tests {
		if got := snRiskLabel(code); got != want {
			t.Errorf("snRiskLabel(%q) = %q, want %q", code, got, want)
		}
	}
}

// TestBuildDriftReevaluationNote verifies the elevated-risk note payload
// posted to ServiceNow on detected drift: it must name the environment,
// show the risk escalation, and enumerate every added/removed/changed
// service so an approver can see exactly what drifted since approval.
func TestBuildDriftReevaluationNote(t *testing.T) {
	envID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	diff := map[string]any{
		"added":   []map[string]string{{"service": "fraud-scoring", "digest": "sha256:newsvc"}},
		"removed": []map[string]string{{"service": "legacy-batch", "digest": "sha256:oldsvc"}},
		"changed": []map[string]string{{"service": "checkout", "from": "sha256:abc123", "to": "sha256:def456"}},
	}

	note := buildDriftReevaluationNote(envID, diff, "4", "2")

	for _, want := range []string{
		envID.String(),
		"Low -> High", // priorRisk=4 (Low) escalated to newRisk=2 (High)
		"Added services (1):",
		"fraud-scoring",
		"Removed services (1):",
		"legacy-batch",
		"Changed services (1):",
		"checkout: sha256:abc123 -> sha256:def456",
		"does not re-score changes post-approval",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q; got:\n%s", want, note)
		}
	}
}

// TestBuildDriftReevaluationNoteNoChanges guards against a note being built
// with empty sections when (hypothetically) called with an empty diff — the
// handler itself never calls buildDriftReevaluationNote unless driftDetected
// is true, but the note builder should still degrade gracefully.
func TestBuildDriftReevaluationNoteNoChanges(t *testing.T) {
	envID := uuid.New()
	diff := map[string]any{
		"added":   []map[string]string{},
		"removed": []map[string]string{},
		"changed": []map[string]string{},
	}
	note := buildDriftReevaluationNote(envID, diff, "3", "2")
	if strings.Contains(note, "Added services") || strings.Contains(note, "Removed services") || strings.Contains(note, "Changed services") {
		t.Errorf("expected no section headers for an empty diff; got:\n%s", note)
	}
	if !strings.Contains(note, "Moderate -> High") {
		t.Errorf("expected risk escalation line; got:\n%s", note)
	}
}
