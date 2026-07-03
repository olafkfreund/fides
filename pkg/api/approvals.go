package api

import (
	"encoding/json"
	"net/http"
	"strings"
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
		// Role distinguishes the segregation-of-duties role this approval
		// represents: "approver" (default, a reviewer sign-off) or "deployer"
		// (the identity that will trigger/perform the deployment).
		Role string `json:"role"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	role := strings.TrimSpace(strings.ToLower(req.Role))
	if role == "" {
		role = "approver"
	}
	if role != "approver" && role != "deployer" {
		http.Error(w, "role must be 'approver' or 'deployer'", http.StatusBadRequest)
		return
	}

	approver := approverIdentity(p)
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO trail_approvals (org_id, trail_id, approved_by, approver_kind, reason, role)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (trail_id, approved_by) DO UPDATE SET reason = EXCLUDED.reason, role = EXCLUDED.role, created_at = CURRENT_TIMESTAMP`,
		p.OrgID, trailID, approver, p.Kind, req.Reason, role); err != nil {
		internalError(w, err)
		return
	}

	resp := map[string]any{"status": "approved", "approved_by": approver, "kind": p.Kind, "role": role}
	// Refresh the segregation-of-duties evidence (committer != approver !=
	// deployer) on every recorded approval. Best-effort: never fails the
	// approval the caller is recording.
	if sod := s.emitSegregationOfDutiesAttestation(r.Context(), p.OrgID, trailID); sod != nil {
		resp["segregation_of_duties"] = sod
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
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
		`SELECT approved_by, approver_kind, COALESCE(reason, ''), COALESCE(NULLIF(role, ''), 'approver'), created_at
		 FROM trail_approvals WHERE trail_id = $1 AND org_id = $2 ORDER BY created_at`, trailID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var by, kind, reason, role string
		var created time.Time
		if err := rows.Scan(&by, &kind, &reason, &role, &created); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"approved_by": by, "approver_kind": kind, "reason": reason, "role": role, "created_at": created})
	}
	writeJSON(w, out)
}
