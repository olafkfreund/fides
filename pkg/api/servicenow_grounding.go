package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/ledger"
)

// handleServiceNowGrounding returns an authoritative "grounding pack" for a
// ServiceNow change request, so ServiceNow's Now Assist answers change and
// compliance questions from Fides's deterministic control-coverage + evidence
// instead of guessing. "Fides advises, ServiceNow decides." (#216)
//
// GET /api/v1/servicenow/grounding?change=CHGxxxx
//
// It resolves the change -> linked controls + trail via change_control_links,
// then reuses the change-gate verdict and the tamper-evident evidence bundle to
// produce both structured fields and a natural-language `grounding_summary` that
// Now Assist can quote verbatim.
func (s *Server) handleServiceNowGrounding(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	change := strings.TrimSpace(r.URL.Query().Get("change"))
	if change == "" {
		http.Error(w, "change is required", http.StatusBadRequest)
		return
	}
	pack, grounded, err := s.groundChange(r.Context(), orgID, change)
	if err != nil {
		internalError(w, err)
		return
	}
	if !grounded {
		w.WriteHeader(http.StatusNotFound)
	}
	writeJSON(w, pack)
}

// groundChange builds the authoritative grounding pack for a change (shared by
// the HTTP endpoint and the MCP `ground_change` tool). The bool is false when no
// Fides evidence is linked to the change.
func (s *Server) groundChange(ctx context.Context, orgID uuid.UUID, change string) (map[string]any, bool, error) {
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT DISTINCT l.trail_id, c.key, c.name, l.attestation_id, t.created_at
		 FROM change_control_links l
		 JOIN controls c ON c.id = l.control_id
		 JOIN trails t ON t.id = l.trail_id
		 WHERE l.org_id = $1 AND l.change_number = $2
		 ORDER BY t.created_at DESC`, orgID, change)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	controls := []map[string]any{}
	controlKeys := []string{}
	trails := []string{}
	seen := map[string]bool{}
	var primaryTrail uuid.UUID
	for rows.Next() {
		var trailID uuid.UUID
		var key, name, attID string
		var createdAt time.Time
		if err := rows.Scan(&trailID, &key, &name, &attID, &createdAt); err != nil {
			return nil, false, err
		}
		controls = append(controls, map[string]any{"control": key, "name": name, "attestation_id": attID})
		controlKeys = append(controlKeys, key)
		if !seen[trailID.String()] {
			seen[trailID.String()] = true
			trails = append(trails, trailID.String())
			if primaryTrail == uuid.Nil {
				primaryTrail = trailID // first row is the most recent trail (ORDER BY created_at DESC)
			}
		}
	}

	if len(controls) == 0 {
		return map[string]any{
			"change_number": change,
			"grounded":      false,
			"grounding_summary": fmt.Sprintf(
				"No Fides evidence is linked to change %s. Fides has no control-coverage or attestations to ground this change; treat its compliance as UNVERIFIED.", change),
		}, false, nil
	}

	gate, err := s.computeChangeGate(ctx, orgID, primaryTrail)
	if err != nil {
		return nil, false, err
	}
	bundle, err := s.computeEvidenceBundle(ctx, primaryTrail)
	if err != nil {
		return nil, false, err
	}

	passed, _ := gate["passed"].([]string)
	failed, _ := gate["failed"].([]map[string]any)
	missing, _ := gate["missing_evidence"].([]map[string]any)
	satisfied := len(passed)
	total := satisfied + len(failed) + len(missing)

	riskScore, _ := gate["risk_score"].(int)
	riskLevel, _ := gate["risk_level"].(string)
	recommendation, _ := gate["recommendation"].(string)
	approved, _ := gate["approved"].(bool)

	attCounts, _ := gate["attestations"].(map[string]int)
	attTotal := attCounts["total"]
	attNonCompliant := attCounts["non_compliant"]

	chainIntact := true
	if v, ok := bundle["chain"].(ledger.Verdict); ok {
		chainIntact = v.Valid
	}
	chainStatus := "intact"
	if !chainIntact {
		chainStatus = "BROKEN"
	}

	summary := fmt.Sprintf(
		"Change %s is linked to %d Fides control(s): %s. Coverage: %d of %d required controls have current compliant evidence (%d failing, %d missing). Change-gate risk: %d/100 (%s); recommendation: %s. Evidence: %d attestation(s), %d non-compliant; tamper-evidence chain %s. Source: Fides (advisory — ServiceNow decides).",
		change, len(controlKeys), strings.Join(uniqueStrings(controlKeys), ", "),
		satisfied, total, len(failed), len(missing),
		riskScore, riskLevel, strings.ToUpper(recommendation),
		attTotal, attNonCompliant, chainStatus)

	return map[string]any{
		"change_number":   change,
		"grounded":        true,
		"trails":          trails,
		"controls_linked": controls,
		"coverage": map[string]any{
			"total_required": total,
			"satisfied":      satisfied,
			"failed":         len(failed),
			"missing":        len(missing),
			"passed":         passed,
		},
		"risk": map[string]any{
			"score":          riskScore,
			"level":          riskLevel,
			"recommendation": recommendation,
			"approved":       approved,
		},
		"evidence": map[string]any{
			"attestations_total": attTotal,
			"non_compliant":      attNonCompliant,
			"by_type":            bundle["attestation_types"],
			"tamper_evident":     chainIntact,
		},
		"grounding_summary": summary,
	}, true, nil
}

// uniqueStrings preserves order while removing duplicates (a change may link the
// same control via multiple attestations).
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
