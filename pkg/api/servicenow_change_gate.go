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

// handleServiceNowChangeGate evaluates a trail's change-gate and writes the
// verdict + risk back onto a ServiceNow Change Request as a work note and risk
// field — Fides advises, ServiceNow decides.
func (s *Server) handleServiceNowChangeGate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		TrailID      string `json:"trail_id"`
		ChangeNumber string `json:"change_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		http.Error(w, "invalid trail_id", http.StatusBadRequest)
		return
	}
	if req.ChangeNumber == "" {
		http.Error(w, "change_number is required", http.StatusBadRequest)
		return
	}

	gate, err := s.computeChangeGate(r.Context(), orgID, trailID)
	if err != nil {
		internalError(w, err)
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

	// ServiceNow change risk: 2=High, 3=Moderate, 4=Low.
	riskField := "4"
	switch gate["risk_level"] {
	case "high":
		riskField = "2"
	case "medium":
		riskField = "3"
	}

	note := buildGateNote(gate)
	if _, err := client.UpdateRecord(r.Context(), "change_request", sysID, map[string]any{
		"work_notes": note,
		"risk":       riskField,
	}); err != nil {
		internalError(w, err)
		return
	}

	if orgID2, ok := principalOrg(r); ok {
		_ = events.Enqueue(r.Context(), s.DB, orgID2, "servicenow.change_gate", map[string]any{
			"change_number": req.ChangeNumber, "trail_id": req.TrailID,
			"recommendation": gate["recommendation"], "risk_score": gate["risk_score"],
		})
	}

	writeJSON(w, map[string]any{
		"change_number":  req.ChangeNumber,
		"sys_id":         sysID,
		"written":        true,
		"recommendation": gate["recommendation"],
		"risk_score":     gate["risk_score"],
		"gate":           gate,
	})
}

func buildGateNote(gate map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fides Change Gate — recommendation: %v (risk %v / %v)\n%v\n",
		gate["recommendation"], gate["risk_score"], gate["risk_level"], gate["summary"])
	if passed, ok := gate["passed"].([]string); ok && len(passed) > 0 {
		fmt.Fprintf(&b, "Passed controls: %s\n", strings.Join(passed, ", "))
	}
	if failed, ok := gate["failed"].([]map[string]any); ok && len(failed) > 0 {
		b.WriteString("Failed controls:\n")
		for _, f := range failed {
			fmt.Fprintf(&b, "  - %v (%v): %v\n", f["control"], f["name"], f["reasons"])
		}
	}
	if missing, ok := gate["missing_evidence"].([]map[string]any); ok && len(missing) > 0 {
		b.WriteString("Missing evidence:\n")
		for _, m := range missing {
			fmt.Fprintf(&b, "  - %v (%v): %v\n", m["control"], m["name"], m["reasons"])
		}
	}
	return b.String()
}
