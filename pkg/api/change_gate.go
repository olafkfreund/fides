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

	// Segregation of duties: count distinct human (session) approvers.
	approverList := []string{}
	humanApprovers := 0
	if arows, aerr := s.q(ctx).QueryContext(ctx,
		`SELECT approved_by, approver_kind FROM trail_approvals WHERE trail_id = $1 ORDER BY created_at`, trailID); aerr == nil {
		for arows.Next() {
			var by, kind string
			if arows.Scan(&by, &kind) == nil {
				approverList = append(approverList, by)
				if kind == "session" {
					humanApprovers++
				}
			}
		}
		arows.Close()
	}

	risk := len(failed)*25 + len(missing)*15 + nonCompliant*10
	if humanApprovers == 0 {
		risk += 20 // no human sign-off (segregation of duties)
	}
	if risk > 100 {
		risk = 100
	}
	level := "low"
	if risk >= 50 {
		level = "high"
	} else if risk >= 20 {
		level = "medium"
	}
	approved := len(failed) == 0 && len(missing) == 0 && humanApprovers >= 1
	recommendation := "hold"
	summary := ""
	switch {
	case approved:
		recommendation = "approve"
		summary = "All controls satisfied by compliant evidence and a human sign-off is present; safe to approve."
	case len(failed) > 0:
		summary = "Failing controls present — do not approve until remediated."
	case len(missing) > 0:
		summary = "Evidence is missing for some controls — approval requires the missing attestations."
	default:
		summary = "Controls satisfied, but awaiting a human approval (segregation of duties)."
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
		"approvals": map[string]any{
			"count":           len(approverList),
			"human_approvers": humanApprovers,
			"four_eyes":       humanApprovers >= 2,
			"approvers":       approverList,
		},
		"summary": summary,
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
	// Refresh the segregation-of-duties evidence (committer != approver !=
	// deployer) as part of the gate evaluation. Best-effort: never fails the
	// gate verdict the caller is waiting on.
	if sod := s.emitSegregationOfDutiesAttestation(r.Context(), orgID, trailID); sod != nil {
		out["segregation_of_duties"] = sod
	}
	writeJSON(w, out)
}
