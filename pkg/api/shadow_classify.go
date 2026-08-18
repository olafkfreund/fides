package api

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// serviceHasPriorApproval reports whether this service has, at some point in
// this environment, run a digest that is on the environment's allowlist.
//
// It is the difference between the two things that look identical in a verdict
// today (#432):
//
//	"nginx is running something nobody has ever approved"          <- a surprise
//	"the reporter you approved last month was patched last night"  <- routine
//
// Both are unapproved and both must stay non-compliant -- this changes the
// message, never the verdict. The point is that an operator who cannot tell
// them apart learns to approve digests without looking, which is the opposite
// of what the allowlist is for. The images affected are exactly the ones
// patched most often and by someone other than the app team: databases,
// ingress controllers, cert-manager, and Fides' own reporter, which allowlists
// itself and so red-flags its own environment on every upgrade.
func serviceHasPriorApproval(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, envID uuid.UUID, serviceName string) bool {
	if serviceName == "" {
		return false
	}
	var found bool
	// A digest this service ran before, which the operator explicitly approved
	// for this environment. Scoped to the environment on BOTH sides: an
	// approval in one environment says nothing about another.
	err := q.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM snapshot_artifacts sa
			JOIN environment_snapshots s  ON s.id = sa.snapshot_id
			JOIN environment_allowlist al ON al.artifact_sha256 = sa.runtime_digest
			                             AND al.environment_id  = s.environment_id
			WHERE s.environment_id = $1
			  AND sa.service_name  = $2
		)`, envID, serviceName).Scan(&found)
	if err != nil {
		// Unknown means "treat it as a surprise". Downgrading the message on a
		// query failure would be the one direction that loses signal.
		return false
	}
	return found
}

// shadowMessage renders the verdict line for an unapproved running digest.
func shadowMessage(serviceName, digest string, priorApproval bool) string {
	if priorApproval {
		return "service " + serviceName + " running unapproved upgrade of a previously approved image, digest " +
			digest + " (approve the new digest to clear this)"
	}
	return "service " + serviceName + " running unregistered digest " + digest
}
