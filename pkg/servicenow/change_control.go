package servicenow

import (
	"context"
	"fmt"
	"time"
)

// ControlLinkNote formats the change_request work note that records which
// Fides control was implemented by this change, and which attestation (piece
// of evidence) proves it — so an auditor reading the change in ServiceNow can
// trace straight to the Fides evidence without leaving the change record.
func ControlLinkNote(controlKey, controlName, attestationID string, attestedAt time.Time) string {
	if controlName != "" {
		return fmt.Sprintf("Fides: this change implements control %s (%s), attested at %s via Fides attestation %s.",
			controlKey, controlName, attestedAt.UTC().Format(time.RFC3339), attestationID)
	}
	return fmt.Sprintf("Fides: this change implements control %s, attested at %s via Fides attestation %s.",
		controlKey, attestedAt.UTC().Format(time.RFC3339), attestationID)
}

// ControlLinkFields builds the change_request fields to write back. work_notes
// is always understood by ServiceNow. The u_fides_* fields are best-effort:
// ServiceNow's Table API silently ignores fields that don't exist on the
// table, so instances that have added those custom fields (e.g. via the
// Fides ServiceNow app/update set) get the control key and attestation id as
// first-class, reportable fields; instances that haven't just get the note.
func ControlLinkFields(controlKey, controlName, attestationID string, attestedAt time.Time) map[string]any {
	return map[string]any{
		"work_notes":             ControlLinkNote(controlKey, controlName, attestationID, attestedAt),
		"u_fides_control":        controlKey,
		"u_fides_attestation_id": attestationID,
		"u_fides_attested_at":    attestedAt.UTC().Format(time.RFC3339),
	}
}

// WriteControlLink looks up the change_request by number and, if found,
// writes the control/attestation reference onto it (work note + best-effort
// custom fields). found is false (with a nil error) when the change_request
// does not exist in ServiceNow — the caller can still persist the Fides-side
// linkage record and surface that the ServiceNow write was skipped.
func WriteControlLink(ctx context.Context, client *Client, changeNumber, controlKey, controlName, attestationID string, attestedAt time.Time) (sysID string, found bool, err error) {
	cr, found, err := QueryChangeRequest(ctx, client, "number="+changeNumber)
	if err != nil {
		return "", false, fmt.Errorf("servicenow: query change_request %s: %w", changeNumber, err)
	}
	if !found {
		return "", false, nil
	}
	sysID = str(cr["sys_id"])
	if sysID == "" {
		return "", true, fmt.Errorf("servicenow: change_request %s has no sys_id", changeNumber)
	}
	fields := ControlLinkFields(controlKey, controlName, attestationID, attestedAt)
	if _, err := client.UpdateRecord(ctx, "change_request", sysID, fields); err != nil {
		return sysID, true, fmt.Errorf("servicenow: update change_request %s: %w", changeNumber, err)
	}
	return sysID, true, nil
}
