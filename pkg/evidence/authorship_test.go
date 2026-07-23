package evidence

import "testing"

func TestParseAuthorship(t *testing.T) {
	aiCommit := `fix(sod): skip recording verdict while role evidence is incomplete

Some body text.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AhR4abvf8YbtMhf7XwPcrZ`

	tests := []struct {
		name          string
		msg           string
		wantKind      string
		wantReviewer  string
		wantCompliant bool
	}{
		{
			name:          "human commit, no trailers",
			msg:           "chore: bump deps\n\nRoutine update.",
			wantKind:      "human",
			wantCompliant: true,
		},
		{
			name:          "ai-authored without reviewer is non-compliant",
			msg:           aiCommit,
			wantKind:      "ai_agent",
			wantCompliant: false,
		},
		{
			name:          "ai-authored with human reviewer is compliant",
			msg:           aiCommit + "\nReviewed-by: Olaf <olaf@freundcloud.com>",
			wantKind:      "ai_agent",
			wantReviewer:  "Olaf <olaf@freundcloud.com>",
			wantCompliant: true,
		},
		{
			name:          "human co-author does not flip kind",
			msg:           "feat: thing\n\nCo-Authored-By: Jane Dev <jane@example.com>",
			wantKind:      "human",
			wantCompliant: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ParseAuthorship(tt.msg)
			if a.AuthorKind != tt.wantKind {
				t.Errorf("AuthorKind = %q, want %q", a.AuthorKind, tt.wantKind)
			}
			if a.HumanReviewer != tt.wantReviewer {
				t.Errorf("HumanReviewer = %q, want %q", a.HumanReviewer, tt.wantReviewer)
			}
			if got := a.Compliant(); got != tt.wantCompliant {
				t.Errorf("Compliant() = %v, want %v", got, tt.wantCompliant)
			}
		})
	}

	// The AI commit's model and session are captured for the attestation payload.
	a := ParseAuthorship(aiCommit)
	if a.Model != "Claude Opus 4.8" {
		t.Errorf("Model = %q, want %q", a.Model, "Claude Opus 4.8")
	}
	if a.AgentSessionID == "" || a.Tool != "claude" {
		t.Errorf("AgentSessionID=%q Tool=%q, want session set and tool=claude", a.AgentSessionID, a.Tool)
	}
}
