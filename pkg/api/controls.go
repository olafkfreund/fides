package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func (s *Server) handleCreateControl(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Key           string   `json:"key"`
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		Framework     string   `json:"framework"`
		RequiredTypes []string `json:"required_types"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Key == "" || req.Name == "" {
		http.Error(w, "key and name are required", http.StatusBadRequest)
		return
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO controls (org_id, key, name, description, framework, required_types)
		 VALUES ($1, $2, $3, $4, NULLIF($5,''), $6)
		 ON CONFLICT (org_id, key) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description,
		   framework = EXCLUDED.framework, required_types = EXCLUDED.required_types, archived = FALSE`,
		p.OrgID, req.Key, req.Name, req.Description, req.Framework, pq.StringArray(req.RequiredTypes)); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"saved"}`))
}

func (s *Server) handleListControls(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	includeArchived := r.URL.Query().Get("include_archived") == "true"
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT id, key, name, COALESCE(description,''), COALESCE(framework,''), required_types, archived
		 FROM controls WHERE org_id = $1 AND ($2 OR NOT archived) ORDER BY key`, orgID, includeArchived)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var key, name, desc, framework string
		var types pq.StringArray
		var archived bool
		if err := rows.Scan(&id, &key, &name, &desc, &framework, &types, &archived); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "key": key, "name": name, "description": desc,
			"framework": framework, "required_types": []string(types), "archived": archived})
	}
	writeJSON(w, out)
}

func (s *Server) setControlArchived(w http.ResponseWriter, r *http.Request, archived bool) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid control id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE controls SET archived = $1 WHERE id = $2 AND org_id = $3`, archived, id, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "control not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}
func (s *Server) handleArchiveControl(w http.ResponseWriter, r *http.Request) {
	s.setControlArchived(w, r, true)
}
func (s *Server) handleUnarchiveControl(w http.ResponseWriter, r *http.Request) {
	s.setControlArchived(w, r, false)
}

// handleControlsCoverage reports, per active control, which environments enforce
// it — i.e. have an enabled policy requiring all of the control's attestation
// types — plus a coverage percentage over the org's environments.
func (s *Server) handleControlsCoverage(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var totalEnvs int
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(*) FROM environments WHERE org_id = $1`, orgID).Scan(&totalEnvs); err != nil {
		internalError(w, err)
		return
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT c.key, c.name, COALESCE(c.framework,''), e.name
		 FROM controls c
		 LEFT JOIN environments e ON e.org_id = c.org_id AND EXISTS (
		   SELECT 1 FROM environment_policies p
		   WHERE p.environment_id = e.id AND p.enabled AND c.required_types <@ p.required_types
		 )
		 WHERE c.org_id = $1 AND NOT c.archived
		 ORDER BY c.key, e.name`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type cov struct {
		Key, Name, Framework string
		Enforced             []string
	}
	byKey := map[string]*cov{}
	order := []string{}
	for rows.Next() {
		var key, name, framework string
		var env *string
		if err := rows.Scan(&key, &name, &framework, &env); err != nil {
			internalError(w, err)
			return
		}
		c := byKey[key]
		if c == nil {
			c = &cov{Key: key, Name: name, Framework: framework, Enforced: []string{}}
			byKey[key] = c
			order = append(order, key)
		}
		if env != nil {
			c.Enforced = append(c.Enforced, *env)
		}
	}
	out := []map[string]any{}
	for _, k := range order {
		c := byKey[k]
		pct := 0.0
		if totalEnvs > 0 {
			pct = float64(len(c.Enforced)) / float64(totalEnvs)
		}
		out = append(out, map[string]any{"control": c.Key, "name": c.Name, "framework": c.Framework,
			"enforced_in": c.Enforced, "coverage": pct})
	}
	writeJSON(w, map[string]any{"total_environments": totalEnvs, "controls": out})
}

// handleEnforceControl enforces a control in one environment (or all of the org's
// environments when {"all": true}) by upserting an enabled environment policy that
// requires the control's evidence types. This is the one-click path from the
// Controls coverage view to raise a control that reads 0% (i.e. no environment
// policy yet requires its attestation types).
func (s *Server) handleEnforceControl(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "control key is required", http.StatusBadRequest)
		return
	}
	var req struct {
		EnvironmentID string `json:"environment_id"`
		All           bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.EnvironmentID == "" && !req.All {
		http.Error(w, "environment_id or all is required", http.StatusBadRequest)
		return
	}

	// Look up the control and the evidence types it requires.
	var name string
	var types pq.StringArray
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT name, required_types FROM controls WHERE org_id = $1 AND key = $2 AND NOT archived`,
		p.OrgID, key).Scan(&name, &types)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "control not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if len(types) == 0 {
		http.Error(w, "control has no required evidence types to enforce", http.StatusBadRequest)
		return
	}

	// Resolve the target environments.
	var envIDs []uuid.UUID
	if req.All {
		rows, err := s.q(r.Context()).QueryContext(r.Context(),
			`SELECT id FROM environments WHERE org_id = $1`, p.OrgID)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				internalError(w, err)
				return
			}
			envIDs = append(envIDs, id)
		}
	} else {
		envID, err := uuid.Parse(req.EnvironmentID)
		if err != nil {
			http.Error(w, "invalid environment id", http.StatusBadRequest)
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
		envIDs = append(envIDs, envID)
	}

	// Upsert an enabled policy per environment. The policy is named after the
	// control key so re-enforcing is idempotent and it's recognizable in the
	// environment's policy list.
	polName := "control:" + key
	for _, envID := range envIDs {
		if _, err := s.q(r.Context()).ExecContext(r.Context(),
			`INSERT INTO environment_policies (environment_id, name, required_types, enabled)
			 VALUES ($1, $2, $3, TRUE)
			 ON CONFLICT (environment_id, name) DO UPDATE SET
			   required_types = EXCLUDED.required_types, enabled = TRUE`,
			envID, polName, types); err != nil {
			internalError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"status": "enforced", "control": key, "environments": len(envIDs)})
}
