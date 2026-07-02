package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"fides/pkg/events"
	"fides/pkg/servicenow"
)

// driftReevaluateReq is the body for POST
// /api/v1/environments/{id}/snapshots/reevaluate-change.
type driftReevaluateReq struct {
	ChangeNumber string `json:"change_number"`
	From         string `json:"from"` // optional; defaults to the two most recent snapshots
	To           string `json:"to"`
}

// snRiskLabel maps the ServiceNow change_request risk field's numeric code
// to a readable label (2=High, 3=Moderate, 4=Low — same convention used by
// the change-gate write-back).
func snRiskLabel(code string) string {
	switch code {
	case "2":
		return "High"
	case "3":
		return "Moderate"
	case "4":
		return "Low"
	case "":
		return "unset"
	default:
		return code
	}
}

// elevatedRiskField computes the ServiceNow risk field value a change
// request should carry once post-approval drift is detected. Drift always
// escalates risk to at least "High" (2) — ServiceNow has no native
// post-approval re-scoring, so Fides forces the signal — but never
// *downgrades* a risk the change was already carrying.
func elevatedRiskField(currentRisk string) string {
	if currentRisk == "2" {
		return "2" // already High
	}
	return "2"
}

// driftDetected reports whether a diffSnapshots result contains any
// added/removed/changed services.
func driftDetected(diff map[string]any) bool {
	for _, k := range []string{"added", "removed", "changed"} {
		if entries, ok := diff[k].([]map[string]string); ok && len(entries) > 0 {
			return true
		}
	}
	return false
}

// buildDriftReevaluationNote renders the ServiceNow work note posted when
// post-approval drift is detected against an approved change request.
func buildDriftReevaluationNote(envID uuid.UUID, diff map[string]any, priorRisk, newRisk string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fides Drift Re-evaluation — environment %s drifted after this change was approved.\n", envID)
	fmt.Fprintf(&b, "Risk escalated: %s -> %s (ServiceNow does not re-score changes post-approval; Fides is flagging this in real time).\n",
		snRiskLabel(priorRisk), snRiskLabel(newRisk))

	if added, ok := diff["added"].([]map[string]string); ok && len(added) > 0 {
		fmt.Fprintf(&b, "Added services (%d):\n", len(added))
		for _, e := range added {
			fmt.Fprintf(&b, "  - %s (digest %s)\n", e["service"], e["digest"])
		}
	}
	if removed, ok := diff["removed"].([]map[string]string); ok && len(removed) > 0 {
		fmt.Fprintf(&b, "Removed services (%d):\n", len(removed))
		for _, e := range removed {
			fmt.Fprintf(&b, "  - %s (was digest %s)\n", e["service"], e["digest"])
		}
	}
	if changed, ok := diff["changed"].([]map[string]string); ok && len(changed) > 0 {
		fmt.Fprintf(&b, "Changed services (%d):\n", len(changed))
		for _, e := range changed {
			fmt.Fprintf(&b, "  - %s: %s -> %s\n", e["service"], e["from"], e["to"])
		}
	}
	b.WriteString("Review the change and confirm the running environment still matches what was approved.\n")
	return b.String()
}

// handleDriftReevaluateChange diffs an environment's snapshots and, if drift
// is detected since the change was approved, writes an elevated risk note
// back onto the ServiceNow change request (Fides advises, ServiceNow decides
// — same posture as the change-gate write-back).
func (s *Server) handleDriftReevaluateChange(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	owned, err := s.envInOrg(r.Context(), envID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}

	var req driftReevaluateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.ChangeNumber == "" {
		http.Error(w, "change_number is required", http.StatusBadRequest)
		return
	}

	diff, err := s.diffSnapshots(r.Context(), envID, req.From, req.To)
	if err != nil {
		if err == errNeedTwoSnapshots {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		internalError(w, err)
		return
	}

	if !driftDetected(diff) {
		writeJSON(w, map[string]any{
			"environment_id": envID,
			"change_number":  req.ChangeNumber,
			"drift_detected": false,
			"written":        false,
			"diff":           diff,
		})
		return
	}

	cfg, enabled, err := servicenow.NewDBLoader(s.DB, s.Secrets).ServiceNowConfig(r.Context(), orgID)
	if err != nil || !enabled {
		http.Error(w, "ServiceNow is not configured for this organization", http.StatusBadRequest)
		return
	}
	client, err := servicenow.New(cfg)
	if err != nil {
		internalError(w, err)
		return
	}

	cr, found, err := servicenow.QueryChangeRequest(r.Context(), client, "number="+req.ChangeNumber)
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		http.Error(w, "change request not found: "+req.ChangeNumber, http.StatusNotFound)
		return
	}
	sysID, _ := cr["sys_id"].(string)
	if sysID == "" {
		http.Error(w, "change request has no sys_id", http.StatusInternalServerError)
		return
	}

	priorRisk, _ := cr["risk"].(string)
	newRisk := elevatedRiskField(priorRisk)
	note := buildDriftReevaluationNote(envID, diff, priorRisk, newRisk)

	if _, err := client.UpdateRecord(r.Context(), "change_request", sysID, map[string]any{
		"work_notes": note,
		"risk":       newRisk,
	}); err != nil {
		internalError(w, err)
		return
	}

	_ = events.Enqueue(r.Context(), s.q(r.Context()), orgID, "servicenow.drift_reevaluation", map[string]any{
		"change_number":  req.ChangeNumber,
		"environment_id": envID.String(),
		"drift_detected": true,
		"prior_risk":     priorRisk,
		"escalated_risk": newRisk,
		"added_count":    len(diff["added"].([]map[string]string)),
		"removed_count":  len(diff["removed"].([]map[string]string)),
		"changed_count":  len(diff["changed"].([]map[string]string)),
	})

	writeJSON(w, map[string]any{
		"environment_id": envID,
		"change_number":  req.ChangeNumber,
		"sys_id":         sysID,
		"drift_detected": true,
		"written":        true,
		"prior_risk":     priorRisk,
		"escalated_risk": newRisk,
		"diff":           diff,
	})
}
