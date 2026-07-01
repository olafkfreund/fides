package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// computeChangeGate evaluates a trail's evidence against the org's active
// controls into a change-approval verdict + 0-100 risk score. Reused by the
// HTTP handler and the ServiceNow change-gate write-back.
func (s *Server) computeChangeGate(ctx context.Context, orgID, trailID uuid.UUID) (map[string]any, error) {
	// Per-type compliance on the trail: a type is "met" only if present AND every
	// attestation of that type is compliant.
	typeCompliant := map[string]bool{}
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT type_name, bool_and(is_compliant) FROM attestations WHERE trail_id = $1 GROUP BY type_name`, trailID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var c bool
		if err := rows.Scan(&t, &c); err != nil {
			rows.Close()
			return nil, err
		}
		typeCompliant[t] = c
	}
	rows.Close()

	var nonCompliant, totalAtt int
	_ = s.q(ctx).QueryRowContext(ctx,
		`SELECT count(*) FILTER (WHERE NOT is_compliant), count(*) FROM attestations WHERE trail_id = $1`, trailID).
		Scan(&nonCompliant, &totalAtt)

	crows, err := s.q(ctx).QueryContext(ctx,
		`SELECT key, name, required_types FROM controls WHERE org_id = $1 AND NOT archived ORDER BY key`, orgID)
	if err != nil {
		return nil, err
	}
	defer crows.Close()

	passed := []string{}
	failed := []map[string]any{}
	missing := []map[string]any{}
	for crows.Next() {
		var key, name string
		var req pq.StringArray
		if err := crows.Scan(&key, &name, &req); err != nil {
			return nil, err
		}
		hasFailed, hasMissing := false, false
		reasons := []string{}
		for _, t := range req {
			c, present := typeCompliant[t]
			if !present {
				hasMissing = true
				reasons = append(reasons, "missing "+t)
			} else if !c {
				hasFailed = true
				reasons = append(reasons, "failed "+t)
			}
		}
		entry := map[string]any{"control": key, "name": name, "reasons": reasons}
		switch {
		case hasFailed:
			failed = append(failed, entry)
		case hasMissing:
			missing = append(missing, entry)
		default:
			passed = append(passed, key)
		}
	}

	risk := len(failed)*25 + len(missing)*15 + nonCompliant*10
	if risk > 100 {
		risk = 100
	}
	level := "low"
	if risk >= 50 {
		level = "high"
	} else if risk >= 20 {
		level = "medium"
	}
	approved := len(failed) == 0 && len(missing) == 0
	recommendation := "hold"
	summary := ""
	switch {
	case approved:
		recommendation = "approve"
		summary = "All controls satisfied by compliant evidence; safe to approve."
	case len(failed) > 0:
		summary = "Failing controls present — do not approve until remediated."
	default:
		summary = "Evidence is missing for some controls — approval requires the missing attestations."
	}

	return map[string]any{
		"trail_id":         trailID,
		"approved":         approved,
		"recommendation":   recommendation,
		"risk_score":       risk,
		"risk_level":       level,
		"passed":           passed,
		"failed":           failed,
		"missing_evidence": missing,
		"attestations":     map[string]int{"total": totalAtt, "non_compliant": nonCompliant},
		"summary":          summary,
	}, nil
}

// handleChangeGate returns the evidence-backed change-approval verdict for a trail.
func (s *Server) handleChangeGate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	out, err := s.computeChangeGate(r.Context(), orgID, trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, out)
}
