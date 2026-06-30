package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"fides/pkg/auth"
)

// envInOrg reports whether the environment belongs to the org (ownership guard).
func (s *Server) envInOrg(ctx context.Context, envID, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM environments WHERE id = $1 AND org_id = $2)`, envID, orgID).Scan(&ok)
	return ok, err
}

// handleAddAllowlist approves an artifact digest for an environment.
func (s *Server) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	var req struct {
		ArtifactSHA256 string `json:"artifact_sha256"`
		Reason         string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.ArtifactSHA256 == "" {
		http.Error(w, "artifact_sha256 is required", http.StatusBadRequest)
		return
	}
	owned, err := s.envInOrg(r.Context(), envID, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO environment_allowlist (environment_id, artifact_sha256, approved_by, reason)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (environment_id, artifact_sha256) DO UPDATE SET approved_by = EXCLUDED.approved_by, reason = EXCLUDED.reason, created_at = now()`,
		envID, req.ArtifactSHA256, p.Email, req.Reason); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"approved"}`))
}

// handleListAllowlist lists approvals for an environment, or checks one digest
// when ?sha= is provided (so CI can gate a deploy on prior approval).
func (s *Server) handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	owned, err := s.envInOrg(r.Context(), envID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if sha := r.URL.Query().Get("sha"); sha != "" {
		var approved bool
		if err := s.q(r.Context()).QueryRowContext(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM environment_allowlist WHERE environment_id = $1 AND artifact_sha256 = $2)`,
			envID, sha).Scan(&approved); err != nil {
			internalError(w, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"environment_id": envID, "artifact_sha256": sha, "approved": approved})
		return
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT artifact_sha256, COALESCE(approved_by, ''), COALESCE(reason, ''), created_at
		 FROM environment_allowlist WHERE environment_id = $1 ORDER BY created_at DESC`, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var sha, by, reason string
		var created interface{}
		if err := rows.Scan(&sha, &by, &reason, &created); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"artifact_sha256": sha, "approved_by": by, "reason": reason, "created_at": created})
	}
	json.NewEncoder(w).Encode(out)
}

// handleRemoveAllowlist revokes an artifact's approval for an environment.
func (s *Server) handleRemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	sha := r.PathValue("sha")
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`DELETE FROM environment_allowlist al USING environments e
		 WHERE al.environment_id = e.id AND e.id = $1 AND e.org_id = $2 AND al.artifact_sha256 = $3`,
		envID, orgID, sha)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "approval not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"removed"}`))
}
