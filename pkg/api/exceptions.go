package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type createExceptionReq struct {
	ControlKey    string `json:"control_key"`
	Reason        string `json:"reason"`
	ApprovedBy    string `json:"approved_by"`
	ExpiresAt     string `json:"expires_at"`      // RFC3339 timestamp
	ExpiresInDays int    `json:"expires_in_days"` // alternative to expires_at
}

// handleCreateException records a time-boxed control exception (waiver). Every
// waiver MUST expire — either expires_at (RFC3339) or expires_in_days.
func (s *Server) handleCreateException(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req createExceptionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.ControlKey) == "" || strings.TrimSpace(req.Reason) == "" {
		http.Error(w, "control_key and reason are required", http.StatusBadRequest)
		return
	}
	var expires time.Time
	switch {
	case req.ExpiresAt != "":
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "expires_at must be RFC3339 (e.g. 2026-12-31T00:00:00Z)", http.StatusBadRequest)
			return
		}
		expires = t
	case req.ExpiresInDays > 0:
		expires = time.Now().AddDate(0, 0, req.ExpiresInDays)
	default:
		http.Error(w, "an expiry is required: set expires_at or expires_in_days", http.StatusBadRequest)
		return
	}
	if !expires.After(time.Now()) {
		http.Error(w, "expiry must be in the future", http.StatusBadRequest)
		return
	}

	var id uuid.UUID
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`INSERT INTO control_exceptions (org_id, control_key, reason, approved_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		orgID, req.ControlKey, req.Reason, req.ApprovedBy, expires).Scan(&id)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id": id, "control_key": req.ControlKey, "reason": req.Reason,
		"approved_by": req.ApprovedBy, "expires_at": expires,
	})
}

// handleListExceptions lists the org's exceptions, newest first, with an active
// flag (not revoked and not expired).
func (s *Server) handleListExceptions(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT id, control_key, reason, COALESCE(approved_by, ''), created_at, expires_at, revoked,
		        (NOT revoked AND expires_at > now()) AS active
		 FROM control_exceptions WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var key, reason, approvedBy string
		var created, expires time.Time
		var revoked, active bool
		if err := rows.Scan(&id, &key, &reason, &approvedBy, &created, &expires, &revoked, &active); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, map[string]any{
			"id": id, "control_key": key, "reason": reason, "approved_by": approvedBy,
			"created_at": created, "expires_at": expires, "revoked": revoked, "active": active,
		})
	}
	writeJSON(w, list)
}

// handleRevokeException revokes an exception (idempotent; org-scoped).
func (s *Server) handleRevokeException(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid exception id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE control_exceptions SET revoked = true WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "exception not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"id": id, "revoked": true})
}
