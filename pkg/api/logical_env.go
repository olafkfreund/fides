package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func (s *Server) logicalInOrg(ctx context.Context, id, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM logical_environments WHERE id = $1 AND org_id = $2)`, id, orgID).Scan(&ok)
	return ok, err
}

func (s *Server) handleCreateLogicalEnv(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
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
		`INSERT INTO logical_environments (id, org_id, name, description) VALUES ($1, $2, $3, $4)`,
		id, orgID, req.Name, req.Description); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id, "name": req.Name})
}

func (s *Server) handleListLogicalEnv(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT le.id, le.name, COALESCE(le.description,''), count(m.environment_id)
		 FROM logical_environments le LEFT JOIN logical_environment_members m ON m.logical_id = le.id
		 WHERE le.org_id = $1 GROUP BY le.id ORDER BY le.name`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, desc string
		var members int
		if err := rows.Scan(&id, &name, &desc, &members); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "description": desc, "members": members})
	}
	writeJSON(w, out)
}

func (s *Server) handleAddLogicalMember(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	logicalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		EnvironmentID string `json:"environment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "valid environment_id is required", http.StatusBadRequest)
		return
	}
	// Both the logical env and the physical env must belong to the org.
	lOK, _ := s.logicalInOrg(r.Context(), logicalID, orgID)
	eOK, _ := s.envInOrg(r.Context(), envID, orgID)
	if !lOK || !eOK {
		http.Error(w, "logical or physical environment not found", http.StatusNotFound)
		return
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO logical_environment_members (logical_id, environment_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, logicalID, envID); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"added"}`))
}

func (s *Server) handleRemoveLogicalMember(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	logicalID, e1 := uuid.Parse(r.PathValue("id"))
	envID, e2 := uuid.Parse(r.PathValue("envId"))
	if e1 != nil || e2 != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`DELETE FROM logical_environment_members m USING logical_environments le
		 WHERE m.logical_id = le.id AND le.id = $1 AND le.org_id = $2 AND m.environment_id = $3`,
		logicalID, orgID, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "member not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(`{"status":"removed"}`))
}

// handleLogicalEnvState aggregates the latest running services across all member
// environments into a single unified view.
func (s *Server) handleLogicalEnvState(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	logicalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	owned, err := s.logicalInOrg(r.Context(), logicalID, orgID)
	if err != nil || !owned {
		http.Error(w, "logical environment not found", http.StatusNotFound)
		return
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT e.id, e.name, COALESCE(sa.service_name,''), COALESCE(sa.runtime_digest,'')
		 FROM logical_environment_members m
		 JOIN environments e ON e.id = m.environment_id
		 LEFT JOIN LATERAL (
		   SELECT id FROM environment_snapshots WHERE environment_id = e.id ORDER BY created_at DESC LIMIT 1
		 ) ls ON true
		 LEFT JOIN snapshot_artifacts sa ON sa.snapshot_id = ls.id
		 WHERE m.logical_id = $1
		 ORDER BY e.name, sa.service_name`, logicalID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type envState struct {
		Name     string              `json:"name"`
		Services []map[string]string `json:"services"`
	}
	envs := map[string]*envState{}
	order := []string{}
	for rows.Next() {
		var envIDVal uuid.UUID
		var name, svc, digest string
		if err := rows.Scan(&envIDVal, &name, &svc, &digest); err != nil {
			internalError(w, err)
			return
		}
		key := envIDVal.String()
		if _, ok := envs[key]; !ok {
			envs[key] = &envState{Name: name, Services: []map[string]string{}}
			order = append(order, key)
		}
		if svc != "" {
			envs[key].Services = append(envs[key].Services, map[string]string{"service": svc, "digest": digest})
		}
	}
	out := []map[string]any{}
	for _, k := range order {
		out = append(out, map[string]any{"environment_id": k, "name": envs[k].Name, "services": envs[k].Services})
	}
	writeJSON(w, map[string]any{"logical_environment_id": logicalID, "environments": out})
}
