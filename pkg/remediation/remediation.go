// Package remediation implements policy-driven auto-remediation with
// approval gates. It models a remediation_action state machine
// (proposed -> approved|rejected -> applied) and is deliberately independent
// of the database/HTTP layers so the transition rules can be unit-tested in
// isolation (pkg/api/remediation.go wires it to Postgres and HTTP).
//
// Remediation is restricted to LOW-RISK domains: environment tags, allowlist
// entries, and drift re-sync. An action can never move to Applied without
// first passing through Approved, and approval requires a distinct approver
// from the proposer (segregation of duties), mirroring the existing
// trail_approvals mechanism.
package remediation

import "errors"

// Status is a remediation_action lifecycle state.
type Status string

const (
	StatusProposed Status = "proposed"
	StatusApproved Status = "approved"
	StatusApplied  Status = "applied"
	StatusRejected Status = "rejected"
)

// Domain is a low-risk remediation target. Only these domains are supported;
// anything else (e.g. "delete resource", "rotate credentials") is out of
// scope until this mechanism has more operational track record.
type Domain string

const (
	// DomainEnvTag adds/updates tags on an environment (e.g. to reflect a
	// corrected classification such as "pci-scope=false").
	DomainEnvTag Domain = "env_tag"
	// DomainAllowlistEntry approves an artifact digest to run in an
	// environment (environment_allowlist).
	DomainAllowlistEntry Domain = "allowlist_entry"
	// DomainDriftResync accepts a currently-running (drifted or shadow)
	// digest as the new approved baseline for an environment.
	DomainDriftResync Domain = "drift_resync"
)

var validDomains = map[Domain]bool{
	DomainEnvTag:         true,
	DomainAllowlistEntry: true,
	DomainDriftResync:    true,
}

// ValidDomain reports whether d is one of the supported low-risk domains.
func ValidDomain(d Domain) bool { return validDomains[d] }

var (
	// ErrInvalidDomain is returned when proposing an action outside the
	// supported low-risk domain set.
	ErrInvalidDomain = errors.New("remediation: unsupported domain (must be env_tag, allowlist_entry, or drift_resync)")
	// ErrNotProposed is returned when approving/rejecting an action that is
	// not (or no longer) in the proposed state.
	ErrNotProposed = errors.New("remediation: action is not in the proposed state")
	// ErrNotApproved is returned when attempting to apply an action that has
	// not been approved. This is the core safety invariant: nothing is ever
	// auto-applied without an approval record.
	ErrNotApproved = errors.New("remediation: cannot apply an action that has not been approved")
	// ErrSelfApproval is returned when the approver is the same identity as
	// the proposer (segregation of duties).
	ErrSelfApproval = errors.New("remediation: approver must differ from the proposer (segregation of duties)")
	// ErrEmptyIdentity is returned when a proposer/approver identity is blank.
	ErrEmptyIdentity = errors.New("remediation: identity must not be empty")
)

// Propose validates a new action's domain and proposer identity, returning
// the initial state (Proposed).
func Propose(domain Domain, proposedBy string) (Status, error) {
	if !ValidDomain(domain) {
		return "", ErrInvalidDomain
	}
	if proposedBy == "" {
		return "", ErrEmptyIdentity
	}
	return StatusProposed, nil
}

// Approve validates the proposed -> approved transition, enforcing
// segregation of duties (the approver must not be the proposer).
func Approve(current Status, proposedBy, approvedBy string) (Status, error) {
	if current != StatusProposed {
		return current, ErrNotProposed
	}
	if approvedBy == "" {
		return current, ErrEmptyIdentity
	}
	if proposedBy != "" && proposedBy == approvedBy {
		return current, ErrSelfApproval
	}
	return StatusApproved, nil
}

// Reject validates the proposed -> rejected transition.
func Reject(current Status, rejectedBy string) (Status, error) {
	if current != StatusProposed {
		return current, ErrNotProposed
	}
	if rejectedBy == "" {
		return current, ErrEmptyIdentity
	}
	return StatusRejected, nil
}

// Apply validates the approved -> applied transition. This is the sole gate
// that prevents auto-applying a remediation: it only succeeds when current
// is Approved.
func Apply(current Status, appliedBy string) (Status, error) {
	if current != StatusApproved {
		return current, ErrNotApproved
	}
	if appliedBy == "" {
		return current, ErrEmptyIdentity
	}
	return StatusApplied, nil
}
