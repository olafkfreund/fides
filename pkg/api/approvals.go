package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
)

func approverIdentity(p *auth.Principal) string {
	if p.Email != "" {
		return p.Email
	}
	if p.UserID != uuid.Nil {
		return p.UserID.String()
	}
	return "service-account"
}

// handleRecordApproval records a segregation-of-duties approval on a trail by the
// authenticated principal (a human session or a machine service account).
func (s *Server) handleRecordApproval(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	approver := approverIdentity(p)
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO trail_approvals (org_id, trail_id, approved_by, approver_kind, reason)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (trail_id, approved_by) DO UPDATE SET reason = EXCLUDED.reason, created_at = CURRENT_TIMESTAMP`,
		p.OrgID, trailID, approver, p.Kind, req.Reason); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"status": "approved", "approved_by": approver, "kind": p.Kind})
}

// handleListApprovals lists a trail's approvals.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT approved_by, approver_kind, COALESCE(reason, ''), created_at
		 FROM trail_approvals WHERE trail_id = $1 AND org_id = $2 ORDER BY created_at`, trailID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var by, kind, reason string
		var created time.Time
		if err := rows.Scan(&by, &kind, &reason, &created); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"approved_by": by, "approver_kind": kind, "reason": reason, "created_at": created})
	}
	writeJSON(w, out)
}
