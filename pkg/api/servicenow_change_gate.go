package api

import (
	"encoding/json"
	"net/http"

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

	// Signed evidence bundle: the tamper-evident hash-chain verdict, artifact
	// digests, and per-type attestation counts backing the verdict above.
	// Fides advises with cryptographic evidence; ServiceNow still decides.
	bundle, err := s.computeEvidenceBundle(r.Context(), trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	gate["evidence_bundle"] = bundle

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

	note := servicenow.BuildChangeGateNote(gate)
	if _, err := client.UpdateRecord(r.Context(), "change_request", sysID, map[string]any{
		"work_notes": note,
		"risk":       riskField,
	}); err != nil {
		internalError(w, err)
		return
	}

	if orgID2, ok := principalOrg(r); ok {
		_ = events.Enqueue(r.Context(), s.q(r.Context()), orgID2, "servicenow.change_gate", map[string]any{
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
