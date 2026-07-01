package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// handleCreatePolicyGlobal creates a new named policy (the existing POST
// /api/v1/policies only updates an existing policy's rules by id).
func (s *Server) handleCreatePolicyGlobal(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Rules       string `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	id := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO policies (id, org_id, name, description, rules) VALUES ($1, $2, $3, $4, $5)`,
		id, p.OrgID, req.Name, req.Description, req.Rules); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id, "status": "created"})
}

// handleDeletePolicyGlobal deletes a policy by id (tenant-scoped).
func (s *Server) handleDeletePolicyGlobal(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid policy id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`DELETE FROM policies WHERE id = $1 AND org_id = $2`, id, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"status": "deleted"})
}
