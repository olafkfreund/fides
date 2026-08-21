package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/models"
)

// Tenant settings, users, group mappings, git providers and outbound webhooks —
// the configuration surface behind the portal's Settings page.
//
// Every secret here is stored by REFERENCE (e.g. "fides/aws-access-key"), never
// by value; the value lives in the configured secrets backend.

type tenantSettingsResp struct {
	OrgID   string                        `json:"org_id"`
	Auth    *models.TenantAuthConfig      `json:"auth"`
	Storage *models.TenantStorageSettings `json:"storage"`
	Vault   *models.TenantVaultSettings   `json:"vault"`
	LLM     *models.TenantLLMSettings     `json:"llm"`
}

func (s *Server) handleGetTenantSettings(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgIDStr := orgID.String()
	var err error

	var authConfig models.TenantAuthConfig
	var storageConfig models.TenantStorageSettings
	var vaultConfig models.TenantVaultSettings
	var llmConfig models.TenantLLMSettings

	// 1. Fetch SSO/Auth Settings
	queryAuth := `SELECT id, org_id, provider_name, client_id, client_secret_path, COALESCE(auth_url, ''), COALESCE(token_url, ''), COALESCE(userinfo_url, ''), redirect_uri, enabled 
	              FROM tenant_auth_configs WHERE org_id = $1 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryAuth, orgID).Scan(
		&authConfig.ID, &authConfig.OrgID, &authConfig.ProviderName, &authConfig.ClientID,
		&authConfig.ClientSecretPath, &authConfig.AuthURL, &authConfig.TokenURL, &authConfig.UserInfoURL,
		&authConfig.RedirectURI, &authConfig.Enabled,
	)
	if err == sql.ErrNoRows {
		authConfig.OrgID = orgID
		authConfig.ProviderName = "github"
		authConfig.Enabled = false
	} else if err != nil {
		internalError(w, err)
		return
	}

	// 2. Fetch Storage Settings
	queryStorage := `SELECT id, org_id, storage_driver, COALESCE(s3_endpoint, ''), COALESCE(s3_bucket, ''), COALESCE(s3_access_key_path, ''), COALESCE(s3_secret_key_path, ''), COALESCE(s3_region, ''), COALESCE(gcs_bucket, ''), COALESCE(gcs_credentials_path, ''), COALESCE(azure_container, ''), COALESCE(azure_connection_string_path, '') 
	                 FROM tenant_storage_settings WHERE org_id = $1 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryStorage, orgID).Scan(
		&storageConfig.ID, &storageConfig.OrgID, &storageConfig.StorageDriver, &storageConfig.S3Endpoint,
		&storageConfig.S3Bucket, &storageConfig.S3AccessKeyPath, &storageConfig.S3SecretKeyPath, &storageConfig.S3Region,
		&storageConfig.GCSBucket, &storageConfig.GCSCredentialsPath, &storageConfig.AzureContainer, &storageConfig.AzureConnectionStringPath,
	)
	if err == sql.ErrNoRows {
		storageConfig.OrgID = orgID
		storageConfig.StorageDriver = "local"
	} else if err != nil {
		internalError(w, err)
		return
	}

	// 3. Fetch Vault Settings
	queryVault := `SELECT id, org_id, vault_provider, COALESCE(vault_address, ''), COALESCE(vault_token_path, ''), COALESCE(vault_role, '') 
	               FROM tenant_vault_settings WHERE org_id = $1 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryVault, orgID).Scan(
		&vaultConfig.ID, &vaultConfig.OrgID, &vaultConfig.VaultProvider, &vaultConfig.VaultAddress,
		&vaultConfig.VaultTokenPath, &vaultConfig.VaultRole,
	)
	if err == sql.ErrNoRows {
		vaultConfig.OrgID = orgID
		vaultConfig.VaultProvider = "env"
	} else if err != nil {
		internalError(w, err)
		return
	}

	// 4. Fetch LLM Settings
	queryLLM := `SELECT id, org_id, provider_name, model_name, COALESCE(endpoint_url, ''), COALESCE(api_key_path, ''), COALESCE(aws_region, ''), COALESCE(azure_deployment, '')
	             FROM tenant_llm_settings WHERE org_id = $1 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryLLM, orgID).Scan(
		&llmConfig.ID, &llmConfig.OrgID, &llmConfig.ProviderName, &llmConfig.ModelName,
		&llmConfig.EndpointURL, &llmConfig.APIKeyPath, &llmConfig.AWSRegion, &llmConfig.AzureDeployment,
	)
	if err == sql.ErrNoRows {
		llmConfig.OrgID = orgID
		llmConfig.ProviderName = "ollama"
		llmConfig.ModelName = "llama3:8b"
	} else if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenantSettingsResp{
		OrgID:   orgIDStr,
		Auth:    &authConfig,
		Storage: &storageConfig,
		Vault:   &vaultConfig,
		LLM:     &llmConfig,
	})
}

func (s *Server) handleSaveTenantSettings(w http.ResponseWriter, r *http.Request) {
	var req saveTenantSettingsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	// Tenant scope comes from the authenticated principal, never the request body (H2/IDOR).
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var err error

	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback()

	// Scope this transaction to the tenant so the RLS backstop is enforced on
	// the tenant_* writes below (no-op when RLS is disabled).
	if _, err := tx.ExecContext(r.Context(), "SELECT set_config('app.current_org', $1, true)", orgID.String()); err != nil {
		internalError(w, err)
		return
	}

	if req.Auth != nil {
		queryAuthUpsert := `
			INSERT INTO tenant_auth_configs (org_id, provider_name, client_id, client_secret_path, auth_url, token_url, userinfo_url, redirect_uri, enabled, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
			ON CONFLICT (org_id, provider_name) DO UPDATE SET
				client_id = EXCLUDED.client_id,
				client_secret_path = EXCLUDED.client_secret_path,
				auth_url = EXCLUDED.auth_url,
				token_url = EXCLUDED.token_url,
				userinfo_url = EXCLUDED.userinfo_url,
				redirect_uri = EXCLUDED.redirect_uri,
				enabled = EXCLUDED.enabled,
				updated_at = CURRENT_TIMESTAMP`
		_, err = tx.ExecContext(r.Context(), queryAuthUpsert,
			orgID, req.Auth.ProviderName, req.Auth.ClientID, req.Auth.ClientSecretPath,
			req.Auth.AuthURL, req.Auth.TokenURL, req.Auth.UserInfoURL, req.Auth.RedirectURI, req.Auth.Enabled,
		)
		if err != nil {
			internalError(w, err)
			return
		}
	}

	if req.Storage != nil {
		queryStorageUpsert := `
			INSERT INTO tenant_storage_settings (org_id, storage_driver, s3_endpoint, s3_bucket, s3_access_key_path, s3_secret_key_path, s3_region, gcs_bucket, gcs_credentials_path, azure_container, azure_connection_string_path, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
			ON CONFLICT (org_id) DO UPDATE SET
				storage_driver = EXCLUDED.storage_driver,
				s3_endpoint = EXCLUDED.s3_endpoint,
				s3_bucket = EXCLUDED.s3_bucket,
				s3_access_key_path = EXCLUDED.s3_access_key_path,
				s3_secret_key_path = EXCLUDED.s3_secret_key_path,
				s3_region = EXCLUDED.s3_region,
				gcs_bucket = EXCLUDED.gcs_bucket,
				gcs_credentials_path = EXCLUDED.gcs_credentials_path,
				azure_container = EXCLUDED.azure_container,
				azure_connection_string_path = EXCLUDED.azure_connection_string_path,
				updated_at = CURRENT_TIMESTAMP`
		_, err = tx.ExecContext(r.Context(), queryStorageUpsert,
			orgID, req.Storage.StorageDriver, req.Storage.S3Endpoint, req.Storage.S3Bucket,
			req.Storage.S3AccessKeyPath, req.Storage.S3SecretKeyPath, req.Storage.S3Region,
			req.Storage.GCSBucket, req.Storage.GCSCredentialsPath, req.Storage.AzureContainer, req.Storage.AzureConnectionStringPath,
		)
		if err != nil {
			internalError(w, err)
			return
		}
	}

	if req.Vault != nil {
		queryVaultUpsert := `
			INSERT INTO tenant_vault_settings (org_id, vault_provider, vault_address, vault_token_path, vault_role, updated_at)
			VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
			ON CONFLICT (org_id) DO UPDATE SET
				vault_provider = EXCLUDED.vault_provider,
				vault_address = EXCLUDED.vault_address,
				vault_token_path = EXCLUDED.vault_token_path,
				vault_role = EXCLUDED.vault_role,
				updated_at = CURRENT_TIMESTAMP`
		_, err = tx.ExecContext(r.Context(), queryVaultUpsert,
			orgID, req.Vault.VaultProvider, req.Vault.VaultAddress, req.Vault.VaultTokenPath, req.Vault.VaultRole,
		)
		if err != nil {
			internalError(w, err)
			return
		}
	}

	if req.LLM != nil {
		queryLLMUpsert := `
			INSERT INTO tenant_llm_settings (org_id, provider_name, model_name, endpoint_url, api_key_path, aws_region, azure_deployment, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
			ON CONFLICT (org_id) DO UPDATE SET
				provider_name = EXCLUDED.provider_name,
				model_name = EXCLUDED.model_name,
				endpoint_url = EXCLUDED.endpoint_url,
				api_key_path = EXCLUDED.api_key_path,
				aws_region = EXCLUDED.aws_region,
				azure_deployment = EXCLUDED.azure_deployment,
				updated_at = CURRENT_TIMESTAMP`
		_, err = tx.ExecContext(r.Context(), queryLLMUpsert,
			orgID, req.LLM.ProviderName, req.LLM.ModelName, req.LLM.EndpointURL,
			req.LLM.APIKeyPath, req.LLM.AWSRegion, req.LLM.AzureDeployment,
		)
		if err != nil {
			internalError(w, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		internalError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(), "SELECT id, name, email, role, groups, created_at FROM users WHERE org_id = $1 ORDER BY name", orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []models.User{}
	for rows.Next() {
		var u models.User
		var grps pq.StringArray
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &grps, &u.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		u.OrgID = orgID
		u.Groups = []string(grps)
		list = append(list, u)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// handleSetUserPassword lets an Admin set/reset a user's local-login password.
func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if principal.Role != auth.RoleAdmin {
		http.Error(w, "only Admins can set user passwords", http.StatusForbidden)
		return
	}
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	var req setPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest) // e.g. too short
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE users SET password_hash = $1 WHERE id = $2 AND org_id = $3`,
		hash, userID, principal.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleSaveUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Registering/upserting an org identity is an admin-only directory operation
	// (same gate as setting a user's password) — otherwise any Writer could seed
	// on_behalf_of-eligible identities for segregation-of-duties approvals.
	if principal.Role != auth.RoleAdmin {
		http.Error(w, "only Admins can register users", http.StatusForbidden)
		return
	}

	var u models.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		badRequest(w, err)
		return
	}
	u.OrgID = principal.OrgID

	query := `INSERT INTO users (org_id, name, email, role, groups) 
	          VALUES ($1, $2, $3, $4, $5) 
	          ON CONFLICT (email) DO UPDATE SET 
	              name = EXCLUDED.name, 
	              role = EXCLUDED.role, 
	              groups = EXCLUDED.groups`
	_, err := s.q(r.Context()).ExecContext(r.Context(), query, u.OrgID, u.Name, u.Email, u.Role, pq.StringArray(u.Groups))
	if err != nil {
		internalError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleListGroupMappings(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(), "SELECT id, external_group, role, created_at FROM sso_group_mappings WHERE org_id = $1 ORDER BY external_group", orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []models.SSOGroupMapping{}
	for rows.Next() {
		var gm models.SSOGroupMapping
		if err := rows.Scan(&gm.ID, &gm.ExternalGroup, &gm.Role, &gm.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		gm.OrgID = orgID
		list = append(list, gm)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleSaveGroupMapping(w http.ResponseWriter, r *http.Request) {
	var gm models.SSOGroupMapping
	if err := json.NewDecoder(r.Body).Decode(&gm); err != nil {
		badRequest(w, err)
		return
	}

	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	gm.OrgID = orgID

	query := `INSERT INTO sso_group_mappings (org_id, external_group, role) 
	          VALUES ($1, $2, $3) 
	          ON CONFLICT (org_id, external_group) DO UPDATE SET 
	              role = EXCLUDED.role`
	_, err := s.q(r.Context()).ExecContext(r.Context(), query, gm.OrgID, gm.ExternalGroup, gm.Role)
	if err != nil {
		internalError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT id, org_id, name, url, secret_path, event_types, enabled, created_at, updated_at
		 FROM tenant_webhooks WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []models.TenantWebhook{}
	for rows.Next() {
		var wh models.TenantWebhook
		var types pq.StringArray
		if err := rows.Scan(&wh.ID, &wh.OrgID, &wh.Name, &wh.URL, &wh.SecretPath, &types, &wh.Enabled, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			internalError(w, err)
			return
		}
		wh.EventTypes = []string(types)
		list = append(list, wh)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleSaveWebhook(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var wh models.TenantWebhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		badRequest(w, err)
		return
	}
	if wh.Name == "" || !strings.HasPrefix(wh.URL, "https://") || wh.SecretPath == "" {
		http.Error(w, "name, an https url, and secret_path are required", http.StatusBadRequest)
		return
	}
	_, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO tenant_webhooks (org_id, name, url, secret_path, event_types, enabled, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())
		 ON CONFLICT (org_id, name) DO UPDATE SET
		   url = EXCLUDED.url, secret_path = EXCLUDED.secret_path,
		   event_types = EXCLUDED.event_types, enabled = EXCLUDED.enabled, updated_at = now()`,
		orgID, wh.Name, wh.URL, wh.SecretPath, pq.StringArray(wh.EventTypes), wh.Enabled)
	if err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleListGitProviders(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT id, org_id, provider, host, api_base, token_path, COALESCE(inbound_secret_path, ''), enabled, created_at, updated_at
		 FROM tenant_git_providers WHERE org_id = $1 ORDER BY host`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []models.TenantGitProvider{}
	for rows.Next() {
		var gp models.TenantGitProvider
		if err := rows.Scan(&gp.ID, &gp.OrgID, &gp.Provider, &gp.Host, &gp.APIBase, &gp.TokenPath, &gp.InboundSecretPath, &gp.Enabled, &gp.CreatedAt, &gp.UpdatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, gp)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleSaveGitProvider(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var gp models.TenantGitProvider
	if err := json.NewDecoder(r.Body).Decode(&gp); err != nil {
		badRequest(w, err)
		return
	}
	validGitProvider := map[string]bool{"github": true, "gitlab": true, "bitbucket": true, "azure-devops": true}
	if !validGitProvider[gp.Provider] || gp.Host == "" || gp.APIBase == "" || gp.TokenPath == "" {
		http.Error(w, "provider (github|gitlab|bitbucket|azure-devops), host, api_base, and token_path are required", http.StatusBadRequest)
		return
	}
	_, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO tenant_git_providers (org_id, provider, host, api_base, token_path, inbound_secret_path, enabled, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		 ON CONFLICT (org_id, host) DO UPDATE SET
		   provider = EXCLUDED.provider, api_base = EXCLUDED.api_base,
		   token_path = EXCLUDED.token_path, inbound_secret_path = EXCLUDED.inbound_secret_path,
		   enabled = EXCLUDED.enabled, updated_at = now()`,
		orgID, gp.Provider, gp.Host, gp.APIBase, gp.TokenPath, gp.InboundSecretPath, gp.Enabled)
	if err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
