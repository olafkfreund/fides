package api

import (
	"encoding/json"
	"net/http"
	"strings"

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
	// rules is a JSONB column. Accept a raw jq expression (or newline-separated
	// rules) and normalize to valid JSON so the insert never fails: if it already
	// parses as JSON keep it, otherwise wrap the jq lines in {"jq": [...]}.
	rulesJSON := req.Rules
	if rulesJSON == "" {
		rulesJSON = "{}"
	} else if !json.Valid([]byte(rulesJSON)) {
		lines := []string{}
		for _, l := range strings.Split(req.Rules, "\n") {
			if t := strings.TrimSpace(l); t != "" {
				lines = append(lines, t)
			}
		}
		wrapped, _ := json.Marshal(map[string]any{"jq": lines})
		rulesJSON = string(wrapped)
	}
	id := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO policies (id, org_id, name, description, rules) VALUES ($1, $2, $3, $4, $5)`,
		id, p.OrgID, req.Name, req.Description, rulesJSON); err != nil {
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

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	query := `SELECT id, name, COALESCE(description, '') AS description, rules /* page keys */ FROM policies WHERE org_id = $1`
	rows, err := s.queryPage(r, page, query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type PolicyView struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Target string `json:"target"`
		YAML   string `json:"yaml"`
	}

	list := []*PolicyView{}
	for rows.Next() {
		var p PolicyView
		var rulesBytes []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Target, &rulesBytes); err != nil {
			internalError(w, err)
			return
		}
		p.YAML = string(rulesBytes)
		list = append(list, &p)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	page.write(w, list)
}

type savePolicyReq struct {
	ID   string `json:"id"`
	YAML string `json:"yaml"`
}

func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req savePolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	policyID, err := uuid.Parse(req.ID)
	if err != nil {
		http.Error(w, "invalid policy id", http.StatusBadRequest)
		return
	}
	// Scope the update to the caller's tenant so one org cannot modify another's policy.
	res, err := s.q(r.Context()).ExecContext(r.Context(), "UPDATE policies SET rules = $1 WHERE id = $2 AND org_id = $3", req.YAML, policyID, orgID)
	if err != nil {
		http.Error(w, "failed to save policy", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
