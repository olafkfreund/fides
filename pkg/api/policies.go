package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ----- environment policies CRUD -----

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Name          string   `json:"name"`
		RequiredTypes []string `json:"required_types"`
		IfTag         string   `json:"if_tag"`
		IfValue       string   `json:"if_value"`
		Enabled       *bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Name == "" || len(req.RequiredTypes) == 0 {
		http.Error(w, "name and at least one required_type are required", http.StatusBadRequest)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO environment_policies (environment_id, name, required_types, if_tag, if_value, enabled)
		 VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''), $6)
		 ON CONFLICT (environment_id, name) DO UPDATE SET
		   required_types = EXCLUDED.required_types, if_tag = EXCLUDED.if_tag,
		   if_value = EXCLUDED.if_value, enabled = EXCLUDED.enabled`,
		envID, req.Name, pq.StringArray(req.RequiredTypes), req.IfTag, req.IfValue, enabled); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"saved"}`))
}

func (s *Server) handleListEnvPolicies(w http.ResponseWriter, r *http.Request) {
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
	if err != nil || !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT id, name, required_types, COALESCE(if_tag,''), COALESCE(if_value,''), enabled
		 FROM environment_policies WHERE environment_id = $1 ORDER BY name`, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, ifTag, ifValue string
		var types pq.StringArray
		var enabled bool
		if err := rows.Scan(&id, &name, &types, &ifTag, &ifValue, &enabled); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "required_types": []string(types), "if_tag": ifTag, "if_value": ifValue, "enabled": enabled})
	}
	writeJSON(w, out)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, e1 := uuid.Parse(r.PathValue("id"))
	polID, e2 := uuid.Parse(r.PathValue("policyId"))
	if e1 != nil || e2 != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`DELETE FROM environment_policies p USING environments e
		 WHERE p.id = $1 AND p.environment_id = e.id AND e.id = $2 AND e.org_id = $3`, polID, envID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(`{"status":"deleted"}`))
}

// ----- tags -----

func (s *Server) setTags(w http.ResponseWriter, r *http.Request, table string) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Tags map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	tagsJSON, _ := json.Marshal(req.Tags)
	// table is a fixed internal constant ("flows" | "environments"), never user input.
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		fmt.Sprintf(`UPDATE %s SET tags = $1 WHERE id = $2 AND org_id = $3`, table), string(tagsJSON), id, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(`{"status":"saved"}`))
}

func (s *Server) handleSetFlowTags(w http.ResponseWriter, r *http.Request) {
	s.setTags(w, r, "flows")
}
func (s *Server) handleSetEnvTags(w http.ResponseWriter, r *http.Request) {
	s.setTags(w, r, "environments")
}

// ----- policy check -----

// handlePolicyCheck evaluates a trail against an environment's policies: each
// applicable policy (tag condition matched, or unconditional) requires all its
// attestation types to be present and compliant on the trail.
func (s *Server) handlePolicyCheck(w http.ResponseWriter, r *http.Request) {
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
	trailID, err := uuid.Parse(r.URL.Query().Get("trail"))
	if err != nil {
		http.Error(w, "trail query param (UUID) is required", http.StatusBadRequest)
		return
	}

	// The trail's flow tags (also verifies the trail belongs to the org).
	var tagsBytes []byte
	err = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT COALESCE(f.tags, '{}'::jsonb) FROM trails tr JOIN flows f ON f.id = tr.flow_id WHERE tr.id = $1 AND f.org_id = $2`,
		trailID, orgID).Scan(&tagsBytes)
	if err == sql.ErrNoRows {
		http.Error(w, "trail not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	flowTags := map[string]any{}
	_ = json.Unmarshal(tagsBytes, &flowTags)

	// Compliant attestation types on the trail.
	compliant := map[string]bool{}
	crows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT DISTINCT type_name FROM attestations WHERE trail_id = $1 AND is_compliant = true`, trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	for crows.Next() {
		var tn string
		crows.Scan(&tn)
		compliant[tn] = true
	}
	crows.Close()

	prows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT name, required_types, COALESCE(if_tag,''), COALESCE(if_value,'') FROM environment_policies
		 WHERE environment_id = $1 AND enabled = true`, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer prows.Close()

	overall := true
	results := []map[string]any{}
	for prows.Next() {
		var name, ifTag, ifValue string
		var required pq.StringArray
		if err := prows.Scan(&name, &required, &ifTag, &ifValue); err != nil {
			internalError(w, err)
			return
		}
		applies := ifTag == "" || fmt.Sprint(flowTags[ifTag]) == ifValue
		missing := []string{}
		if applies {
			for _, t := range required {
				if !compliant[t] {
					missing = append(missing, t)
				}
			}
			if len(missing) > 0 {
				overall = false
			}
		}
		results = append(results, map[string]any{"policy": name, "applies": applies, "missing": missing})
	}
	writeJSON(w, map[string]any{"compliant": overall, "trail_id": trailID, "results": results})
}
