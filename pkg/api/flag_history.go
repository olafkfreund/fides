package api

import "net/http"

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
	page, ok := newListPage(w, r, orgID, timeKey("a.created_at"), uuidKey("a.id"), true)
	if !ok {
		return
	}
	rows, err := s.queryPage(r, page,
		`SELECT a.trail_id, a.is_compliant, a.created_at,
		        a.payload->>'flag_key', a.payload->>'environment',
		        a.payload->>'old_state', a.payload->>'new_state',
		        a.payload->>'actor', a.payload->>'source' /* page keys */
		 FROM attestations a
		 JOIN trails tr ON tr.id = a.trail_id
		 JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND a.type_name = $2`, orgID, FlagChangedAttestationType)
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
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	page.write(w, out)
}
