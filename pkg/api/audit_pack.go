package api

import (
	"net/http"
	"time"

	"github.com/lib/pq"
)

// handleAuditPack assembles a single portable evidence bundle for auditors: the
// control catalog (with framework refs + rationale), the risk register (with the
// controls that mitigate each risk), the org's configured controls, and its
// active (in-date) exceptions. Everything comes from data Fides already holds —
// this is just the "Prove" leg packaged in one place. Grows with the timeline /
// gate verdicts as needed.
func (s *Server) handleAuditPack(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	orgControls := []map[string]any{}
	if rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT key, name, required_types FROM controls WHERE org_id = $1 AND NOT archived ORDER BY key`, orgID); err == nil {
		for rows.Next() {
			var key, name string
			var req pq.StringArray
			if rows.Scan(&key, &name, &req) == nil {
				orgControls = append(orgControls, map[string]any{"key": key, "name": name, "required_types": []string(req)})
			}
		}
		rows.Close()
	}

	activeExceptions := []map[string]any{}
	if rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT control_key, reason, COALESCE(approved_by, ''), expires_at
		 FROM control_exceptions WHERE org_id = $1 AND NOT revoked AND expires_at > now()
		 ORDER BY expires_at`, orgID); err == nil {
		for rows.Next() {
			var ck, reason, by string
			var exp time.Time
			if rows.Scan(&ck, &reason, &by, &exp) == nil {
				activeExceptions = append(activeExceptions, map[string]any{
					"control_key": ck, "reason": reason, "approved_by": by, "expires_at": exp,
				})
			}
		}
		rows.Close()
	}

	risks := []riskView{}
	for _, risk := range parsedRiskRegister.Risks {
		risks = append(risks, riskView{riskEntry: risk, MitigatedBy: controlsMitigating(risk.Key)})
	}

	writeJSON(w, map[string]any{
		"generated_at":      time.Now().UTC(),
		"org_id":            orgID,
		"catalog":           parsedControlCatalog,
		"risk_register":     risks,
		"org_controls":      orgControls,
		"active_exceptions": activeExceptions,
		"training":          s.trainingRecords(r, orgID),
	})
}
