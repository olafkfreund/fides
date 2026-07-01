package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// handleListFlowTrails lists the trails belonging to a flow so the UI can offer
// a trail picker instead of asking the user to paste a raw trail UUID.
func (s *Server) handleListFlowTrails(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flowID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid flow id", http.StatusBadRequest)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT t.id, t.name, COALESCE(t.git_commit, ''), COALESCE(t.git_branch, ''), t.created_at,
		        (SELECT COUNT(*) FROM attestations a WHERE a.trail_id = t.id) AS attestations,
		        COALESCE((SELECT bool_and(a.is_compliant) FROM attestations a WHERE a.trail_id = t.id), true) AS compliant
		 FROM trails t JOIN flows f ON f.id = t.flow_id
		 WHERE t.flow_id = $1 AND f.org_id = $2
		 ORDER BY t.created_at DESC LIMIT 200`, flowID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, commit, branch string
		var created time.Time
		var attestations int
		var compliant bool
		if err := rows.Scan(&id, &name, &commit, &branch, &created, &attestations, &compliant); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "git_commit": commit, "git_branch": branch,
			"created_at": created, "attestations": attestations, "compliant": compliant,
		})
	}
	writeJSON(w, out)
}

// handleListFlowArtifacts lists the artifacts recorded across a flow's trails.
func (s *Server) handleListFlowArtifacts(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flowID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid flow id", http.StatusBadRequest)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT a.sha256, a.name, COALESCE(a.type, ''), COALESCE(t.git_commit, ''), a.created_at,
		        COALESCE((SELECT bool_and(at.is_compliant) FROM attestations at WHERE at.trail_id = a.trail_id), true) AS compliant
		 FROM artifacts a JOIN trails t ON t.id = a.trail_id JOIN flows f ON f.id = t.flow_id
		 WHERE t.flow_id = $1 AND f.org_id = $2
		 ORDER BY a.created_at DESC LIMIT 200`, flowID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var sha, name, typ, commit string
		var created time.Time
		var compliant bool
		if err := rows.Scan(&sha, &name, &typ, &commit, &created, &compliant); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"sha256": sha, "name": name, "type": typ, "git_commit": commit, "created_at": created, "compliant": compliant})
	}
	writeJSON(w, out)
}
