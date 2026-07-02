package api

import "testing"

func TestEvaluateSegregationOfDuties(t *testing.T) {
	tests := []struct {
		name          string
		committer     string
		approvers     []string
		deployers     []string
		wantCompliant bool
	}{
		{
			name:          "distinct committer, approver, and deployer is compliant",
			committer:     "dev@example.com",
			approvers:     []string{"reviewer@example.com"},
			deployers:     []string{"ops@example.com"},
			wantCompliant: true,
		},
		{
			name:          "distinct committer and multiple distinct approvers/deployer is compliant",
			committer:     "dev@example.com",
			approvers:     []string{"reviewer1@example.com", "reviewer2@example.com"},
			deployers:     []string{"ops@example.com"},
			wantCompliant: true,
		},
		{
			name:          "committer same as approver is non-compliant",
			committer:     "dev@example.com",
			approvers:     []string{"dev@example.com"},
			deployers:     []string{"ops@example.com"},
			wantCompliant: false,
		},
		{
			name:          "committer same as deployer is non-compliant",
			committer:     "dev@example.com",
			approvers:     []string{"reviewer@example.com"},
			deployers:     []string{"dev@example.com"},
			wantCompliant: false,
		},
		{
			name:          "deployer also acted as approver is non-compliant",
			committer:     "dev@example.com",
			approvers:     []string{"ops@example.com"},
			deployers:     []string{"ops@example.com"},
			wantCompliant: false,
		},
		{
			name:          "missing committer identity is non-compliant",
			committer:     "",
			approvers:     []string{"reviewer@example.com"},
			deployers:     []string{"ops@example.com"},
			wantCompliant: false,
		},
		{
			name:          "no approver recorded is non-compliant",
			committer:     "dev@example.com",
			approvers:     nil,
			deployers:     []string{"ops@example.com"},
			wantCompliant: false,
		},
		{
			name:          "no deployer recorded is non-compliant",
			committer:     "dev@example.com",
			approvers:     []string{"reviewer@example.com"},
			deployers:     nil,
			wantCompliant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateSegregationOfDuties(tt.committer, tt.approvers, tt.deployers)
			if got.Compliant != tt.wantCompliant {
				t.Fatalf("Compliant = %v, want %v (violations: %v)", got.Compliant, tt.wantCompliant, got.Violations)
			}
			if !tt.wantCompliant && len(got.Violations) == 0 {
				t.Fatalf("expected violations to be populated for a non-compliant result")
			}
			if got.Committer != tt.committer {
				t.Fatalf("Committer = %q, want %q", got.Committer, tt.committer)
			}
		})
	}
}

func TestIdentityFromTags(t *testing.T) {
	tests := []struct {
		name string
		tags map[string]string
		want string
	}{
		{
			name: "committer tag preferred",
			tags: map[string]string{"committer": "dev@example.com", "author": "other@example.com"},
			want: "dev@example.com",
		},
		{
			name: "falls back to author tag",
			tags: map[string]string{"author": "dev@example.com"},
			want: "dev@example.com",
		},
		{
			name: "falls back to git_author tag",
			tags: map[string]string{"git_author": "dev@example.com"},
			want: "dev@example.com",
		},
		{
			name: "trims whitespace",
			tags: map[string]string{"committer": "  dev@example.com  "},
			want: "dev@example.com",
		},
		{
			name: "no known tag returns empty",
			tags: map[string]string{"team": "platform"},
			want: "",
		},
		{
			name: "nil tags returns empty",
			tags: nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identityFromTags(tt.tags); got != tt.want {
				t.Fatalf("identityFromTags() = %q, want %q", got, tt.want)
			}
		})
	}
}
