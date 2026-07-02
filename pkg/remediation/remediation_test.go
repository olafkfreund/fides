package remediation

import (
	"errors"
	"testing"
)

func TestValidDomain(t *testing.T) {
	cases := []struct {
		domain Domain
		want   bool
	}{
		{DomainEnvTag, true},
		{DomainAllowlistEntry, true},
		{DomainDriftResync, true},
		{Domain("delete_resource"), false},
		{Domain(""), false},
	}
	for _, tc := range cases {
		if got := ValidDomain(tc.domain); got != tc.want {
			t.Errorf("ValidDomain(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestPropose(t *testing.T) {
	t.Run("valid domain and proposer succeeds", func(t *testing.T) {
		status, err := Propose(DomainEnvTag, "alice@example.com")
		if err != nil {
			t.Fatalf("Propose: unexpected error: %v", err)
		}
		if status != StatusProposed {
			t.Fatalf("Propose: got status %q, want %q", status, StatusProposed)
		}
	})
	t.Run("invalid domain rejected", func(t *testing.T) {
		if _, err := Propose(Domain("rotate_credentials"), "alice@example.com"); !errors.Is(err, ErrInvalidDomain) {
			t.Fatalf("Propose: got err %v, want ErrInvalidDomain", err)
		}
	})
	t.Run("empty proposer rejected", func(t *testing.T) {
		if _, err := Propose(DomainAllowlistEntry, ""); !errors.Is(err, ErrEmptyIdentity) {
			t.Fatalf("Propose: got err %v, want ErrEmptyIdentity", err)
		}
	})
}

func TestApprove(t *testing.T) {
	t.Run("distinct approver succeeds", func(t *testing.T) {
		status, err := Approve(StatusProposed, "alice@example.com", "bob@example.com")
		if err != nil {
			t.Fatalf("Approve: unexpected error: %v", err)
		}
		if status != StatusApproved {
			t.Fatalf("Approve: got status %q, want %q", status, StatusApproved)
		}
	})
	t.Run("self-approval rejected (segregation of duties)", func(t *testing.T) {
		status, err := Approve(StatusProposed, "alice@example.com", "alice@example.com")
		if !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("Approve: got err %v, want ErrSelfApproval", err)
		}
		if status != StatusProposed {
			t.Fatalf("Approve: status must not change on error, got %q", status)
		}
	})
	t.Run("cannot approve a non-proposed action", func(t *testing.T) {
		for _, s := range []Status{StatusApproved, StatusApplied, StatusRejected} {
			if _, err := Approve(s, "alice@example.com", "bob@example.com"); !errors.Is(err, ErrNotProposed) {
				t.Fatalf("Approve(%q): got err %v, want ErrNotProposed", s, err)
			}
		}
	})
	t.Run("empty approver rejected", func(t *testing.T) {
		if _, err := Approve(StatusProposed, "alice@example.com", ""); !errors.Is(err, ErrEmptyIdentity) {
			t.Fatalf("Approve: got err %v, want ErrEmptyIdentity", err)
		}
	})
}

func TestReject(t *testing.T) {
	t.Run("proposed -> rejected succeeds", func(t *testing.T) {
		status, err := Reject(StatusProposed, "bob@example.com")
		if err != nil {
			t.Fatalf("Reject: unexpected error: %v", err)
		}
		if status != StatusRejected {
			t.Fatalf("Reject: got status %q, want %q", status, StatusRejected)
		}
	})
	t.Run("cannot reject a non-proposed action", func(t *testing.T) {
		for _, s := range []Status{StatusApproved, StatusApplied, StatusRejected} {
			if _, err := Reject(s, "bob@example.com"); !errors.Is(err, ErrNotProposed) {
				t.Fatalf("Reject(%q): got err %v, want ErrNotProposed", s, err)
			}
		}
	})
}

// TestApplyRequiresApproval is the core safety invariant of this package:
// an action can never be applied without first being approved.
func TestApplyRequiresApproval(t *testing.T) {
	t.Run("cannot apply a merely-proposed action", func(t *testing.T) {
		status, err := Apply(StatusProposed, "carol@example.com")
		if !errors.Is(err, ErrNotApproved) {
			t.Fatalf("Apply(proposed): got err %v, want ErrNotApproved", err)
		}
		if status != StatusProposed {
			t.Fatalf("Apply(proposed): status must not change on error, got %q", status)
		}
	})
	t.Run("cannot apply a rejected action", func(t *testing.T) {
		if _, err := Apply(StatusRejected, "carol@example.com"); !errors.Is(err, ErrNotApproved) {
			t.Fatalf("Apply(rejected): got err %v, want ErrNotApproved", err)
		}
	})
	t.Run("cannot re-apply an already-applied action", func(t *testing.T) {
		if _, err := Apply(StatusApplied, "carol@example.com"); !errors.Is(err, ErrNotApproved) {
			t.Fatalf("Apply(applied): got err %v, want ErrNotApproved", err)
		}
	})
	t.Run("approved action can be applied", func(t *testing.T) {
		status, err := Apply(StatusApproved, "carol@example.com")
		if err != nil {
			t.Fatalf("Apply(approved): unexpected error: %v", err)
		}
		if status != StatusApplied {
			t.Fatalf("Apply(approved): got status %q, want %q", status, StatusApplied)
		}
	})
	t.Run("empty applier rejected", func(t *testing.T) {
		if _, err := Apply(StatusApproved, ""); !errors.Is(err, ErrEmptyIdentity) {
			t.Fatalf("Apply: got err %v, want ErrEmptyIdentity", err)
		}
	})
}

// TestFullLifecycle walks propose -> approve -> apply end to end.
func TestFullLifecycle(t *testing.T) {
	status, err := Propose(DomainDriftResync, "alice@example.com")
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	status, err = Approve(status, "alice@example.com", "bob@example.com")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	status, err = Apply(status, "bob@example.com")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if status != StatusApplied {
		t.Fatalf("got final status %q, want %q", status, StatusApplied)
	}
}

// TestRejectedLifecycleCannotBeApplied walks propose -> reject -> apply,
// confirming a rejected action can never reach Applied.
func TestRejectedLifecycleCannotBeApplied(t *testing.T) {
	status, err := Propose(DomainEnvTag, "alice@example.com")
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	status, err = Reject(status, "bob@example.com")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if _, err := Apply(status, "bob@example.com"); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("Apply(rejected): got err %v, want ErrNotApproved", err)
	}
}
