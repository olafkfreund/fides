package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/events"
	"fides/pkg/models"
	"fides/pkg/servicenow"
)

// ServiceNow HTTP handlers.
//
// The integration's own logic lives in pkg/servicenow; this file is only the
// HTTP surface the portal and CLI call.

// snowClient builds a ServiceNow client for the tenant. The bool is false when
// ServiceNow is not configured/enabled for the org.
func (s *Server) snowClient(ctx context.Context, orgID uuid.UUID) (*servicenow.Client, bool, error) {
	cfg, enabled, err := servicenow.NewDBLoader(s.DB, s.Secrets).ServiceNowConfig(ctx, orgID)
	if err != nil || !enabled {
		return nil, enabled, err
	}
	c, err := servicenow.New(cfg)
	return c, true, err
}

// handleServiceNowChangeStatus reads a change request's status (no attestation).
func (s *Server) handleServiceNowChangeStatus(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	num := r.URL.Query().Get("change_number")
	ci := r.URL.Query().Get("ci")
	if num == "" && ci == "" {
		http.Error(w, "change_number or ci query param is required", http.StatusBadRequest)
		return
	}
	client, enabled, err := s.snowClient(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured", http.StatusBadRequest)
		return
	}
	query := "number=" + num
	if num == "" {
		query = "cmdb_ci.name=" + ci + "^active=true^ORDERBYDESCsys_updated_on"
	}
	cr, found, err := servicenow.QueryChangeRequest(r.Context(), client, query)
	if err != nil {
		internalError(w, err)
		return
	}
	out := map[string]any{"found": false}
	if found {
		out = servicenow.NormalizeChange(cr)
		out["found"] = true
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

type incidentReq struct {
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	Urgency          string `json:"urgency"`
	CmdbCI           string `json:"cmdb_ci"`
}

// handleServiceNowCreateIncident opens a ServiceNow incident (e.g. on a failed gate).
func (s *Server) handleServiceNowCreateIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req incidentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.ShortDescription == "" {
		http.Error(w, "short_description is required", http.StatusBadRequest)
		return
	}
	client, enabled, err := s.snowClient(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured", http.StatusBadRequest)
		return
	}
	fields := map[string]any{"short_description": req.ShortDescription, "description": req.Description}
	if req.Urgency != "" {
		fields["urgency"] = req.Urgency
	}
	if req.CmdbCI != "" {
		fields["cmdb_ci"] = req.CmdbCI
	}
	rec, err := client.CreateRecord(r.Context(), "incident", fields)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"number": rec["number"], "sys_id": rec["sys_id"]})
}

// handleServiceNowSearchCMDB searches the CMDB for configuration items by name.
func (s *Server) handleServiceNowSearchCMDB(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query param is required", http.StatusBadRequest)
		return
	}
	client, enabled, err := s.snowClient(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured", http.StatusBadRequest)
		return
	}
	res, err := client.QueryTable(r.Context(), "cmdb_ci", "nameLIKE"+name,
		"name", "sys_class_name", "sys_id", "short_description", "managed_by", "owned_by")
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res.Result)
}

type changeCheckReq struct {
	TrailID        string `json:"trail_id"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ChangeNumber   string `json:"change_number"`
	CI             string `json:"ci"` // service / cmdb_ci name (alternative to change_number)
}

// handleServiceNowChangeCheck fetches a ServiceNow change request, evaluates it
// against the servicenow-change attestation type's jq rules, records the
// attestation on the trail, and emits compliance.evaluated. This lets pipelines
// gate on an approved, in-window change record.
func (s *Server) handleServiceNowChangeCheck(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req changeCheckReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		http.Error(w, "valid trail_id is required", http.StatusBadRequest)
		return
	}
	if req.ChangeNumber == "" && req.CI == "" {
		http.Error(w, "change_number or ci is required", http.StatusBadRequest)
		return
	}

	cfg, enabled, err := servicenow.NewDBLoader(s.DB, s.Secrets).ServiceNowConfig(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured for this organization", http.StatusBadRequest)
		return
	}
	client, err := servicenow.New(cfg)
	if err != nil {
		internalError(w, err)
		return
	}

	query := "number=" + req.ChangeNumber
	if req.ChangeNumber == "" {
		query = "cmdb_ci.name=" + req.CI + "^active=true^ORDERBYDESCsys_updated_on"
	}
	cr, found, err := servicenow.QueryChangeRequest(r.Context(), client, query)
	if err != nil {
		internalError(w, err)
		return
	}

	payload := map[string]any{"found": false}
	if found {
		payload = servicenow.NormalizeChange(cr)
		payload["found"] = true
	}
	payloadJSON, _ := json.Marshal(payload)

	// Evaluate against the servicenow-change attestation type's jq rules.
	var rules pq.StringArray
	_ = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT jq_rules FROM attestation_types WHERE name = 'servicenow-change' AND org_id = $1 LIMIT 1`, orgID).Scan(&rules)
	rulesOK, failed, _ := s.PolicyEngine.EvaluateAttestation(string(payloadJSON), []string(rules))
	compliant := found && rulesOK

	// Record the attestation on the trail (with tamper-evidence chain).
	contentHash, prevHash, err := s.attestationChain(r.Context(), trailID, "servicenow-change-check", "servicenow-change", string(payloadJSON), compliant)
	if err != nil {
		internalError(w, err)
		return
	}
	_, err = s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO attestations (id, trail_id, name, type_name, payload, is_compliant, content_hash, prev_hash, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`,
		uuid.New(), trailID, "servicenow-change-check", "servicenow-change", string(payloadJSON), compliant, contentHash, prevHash)
	if err != nil {
		internalError(w, err)
		return
	}

	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		_ = events.Enqueue(r.Context(), s.q(r.Context()), orgID, "compliance.evaluated", map[string]any{
			"trail_id": trailID.String(), "attestation": "servicenow-change", "compliant": compliant,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"compliant":     compliant,
		"found":         found,
		"change_number": str2(payload["number"]),
		"failed_rules":  failed,
	})
}

func str2(v any) string {
	if sv, ok := v.(string); ok {
		return sv
	}
	return ""
}

func (s *Server) handleGetServiceNow(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var sn models.TenantServiceNowSettings
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT id, org_id, instance_url, auth_type, client_id, secret_path, enabled, created_at, updated_at
		 FROM tenant_servicenow_settings WHERE org_id = $1`, orgID).
		Scan(&sn.ID, &sn.OrgID, &sn.InstanceURL, &sn.AuthType, &sn.ClientID, &sn.SecretPath, &sn.Enabled, &sn.CreatedAt, &sn.UpdatedAt)
	w.Header().Set("Content-Type", "application/json")
	if err == sql.ErrNoRows {
		json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	json.NewEncoder(w).Encode(sn)
}

func (s *Server) handleSaveServiceNow(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var sn models.TenantServiceNowSettings
	if err := json.NewDecoder(r.Body).Decode(&sn); err != nil {
		badRequest(w, err)
		return
	}
	if !strings.HasPrefix(sn.InstanceURL, "https://") || (sn.AuthType != "basic" && sn.AuthType != "oauth2") || sn.ClientID == "" || sn.SecretPath == "" {
		http.Error(w, "https instance_url, auth_type (basic|oauth2), client_id, and secret_path are required", http.StatusBadRequest)
		return
	}
	_, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO tenant_servicenow_settings (org_id, instance_url, auth_type, client_id, secret_path, enabled, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())
		 ON CONFLICT (org_id) DO UPDATE SET
		   instance_url = EXCLUDED.instance_url, auth_type = EXCLUDED.auth_type,
		   client_id = EXCLUDED.client_id, secret_path = EXCLUDED.secret_path,
		   enabled = EXCLUDED.enabled, updated_at = now()`,
		orgID, sn.InstanceURL, sn.AuthType, sn.ClientID, sn.SecretPath, sn.Enabled)
	if err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
