package api

import (
	"net/http"
	"strconv"
)

// handleFlagHistory lists an org's recent feature-flag changes (the flag.changed
// attestations across its feature-flags flow) for auditors and the /admin
// console — completing the flag-governance audit surface (#291).
// GET /api/v1/flags/history?limit=N
func (s *Server) handleFlagHistory(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT a.trail_id, a.is_compliant, a.created_at,
		        a.payload->>'flag_key', a.payload->>'environment',
		        a.payload->>'old_state', a.payload->>'new_state',
		        a.payload->>'actor', a.payload->>'source'
		 FROM attestations a
		 JOIN trails tr ON tr.id = a.trail_id
		 JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND a.type_name = $2
		 ORDER BY a.created_at DESC LIMIT $3`, orgID, FlagChangedAttestationType, limit)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var trailID, flagKey, env, oldSt, newSt, actor, source string
		var compliant bool
		var created any
		if err := rows.Scan(&trailID, &compliant, &created, &flagKey, &env, &oldSt, &newSt, &actor, &source); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{
			"trail_id": trailID, "flag_key": flagKey, "environment": env,
			"old_state": oldSt, "new_state": newSt, "actor": actor,
			"source": source, "compliant": compliant, "recorded_at": created,
		})
	}
	writeJSON(w, out)
}
