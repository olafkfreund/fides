package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

func (s *Server) handleGetSlack(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var secretPath string
	var enabled bool
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT webhook_secret_path, enabled FROM tenant_slack_settings WHERE org_id = $1`, orgID).Scan(&secretPath, &enabled)
	w.Header().Set("Content-Type", "application/json")
	if err == sql.ErrNoRows {
		w.Write([]byte(`{"enabled":false}`))
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"webhook_secret_path": secretPath, "enabled": enabled})
}

func (s *Server) handleSaveSlack(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		WebhookSecretPath string `json:"webhook_secret_path"`
		Enabled           bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.WebhookSecretPath == "" {
		http.Error(w, "webhook_secret_path is required", http.StatusBadRequest)
		return
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO tenant_slack_settings (org_id, webhook_secret_path, enabled, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (org_id) DO UPDATE SET webhook_secret_path = EXCLUDED.webhook_secret_path, enabled = EXCLUDED.enabled, updated_at = now()`,
		orgID, req.WebhookSecretPath, req.Enabled); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"saved"}`))
}
