package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/crypto"
)

// API key format: fides_<prefix>_<secret>. The prefix is a public lookup id; only
// a scrypt hash of the secret is stored.
const keyScheme = "fides_"

func generateAPIKey() (full, prefix, secret string, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 24)
	if _, err = rand.Read(pb); err != nil {
		return
	}
	if _, err = rand.Read(sb); err != nil {
		return
	}
	prefix = hex.EncodeToString(pb)
	secret = hex.EncodeToString(sb)
	full = keyScheme + prefix + "_" + secret
	return
}

func parseAPIKey(token string) (prefix, secret string, ok bool) {
	if !strings.HasPrefix(token, keyScheme) {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(token, keyScheme), "_", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// authServiceAccountKey authenticates a bearer token as a service-account key.
// Returns nil if it is not a valid, enabled, unexpired, unrevoked key.
func (s *Server) authServiceAccountKey(ctx context.Context, token string) *auth.Principal {
	prefix, secret, ok := parseAPIKey(token)
	if !ok || s.DB == nil {
		return nil
	}
	var (
		orgID     uuid.UUID
		role      string
		enabled   bool
		keyID     uuid.UUID
		keyHash   string
		expiresAt *time.Time
		revokedAt *time.Time
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT sa.org_id, sa.role, sa.enabled, k.id, k.key_hash, k.expires_at, k.revoked_at
		 FROM service_account_keys k JOIN service_accounts sa ON sa.id = k.service_account_id
		 WHERE k.prefix = $1`, prefix).Scan(&orgID, &role, &enabled, &keyID, &keyHash, &expiresAt, &revokedAt)
	if err != nil {
		return nil
	}
	if !enabled || revokedAt != nil {
		return nil
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil
	}
	if !crypto.VerifyPassword(secret, keyHash) {
		return nil
	}
	// Best-effort last-used stamp.
	_, _ = s.DB.ExecContext(ctx, `UPDATE service_account_keys SET last_used_at = now() WHERE id = $1`, keyID)
	return &auth.Principal{OrgID: orgID, Role: role, Kind: "service"}
}

// ----- management handlers (Admin only) -----

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	if p.Role != auth.RoleAdmin {
		http.Error(w, "only Admins can manage service accounts", http.StatusForbidden)
		return nil, false
	}
	return p, true
}

func validRole(role string) bool {
	switch role {
	case auth.RoleAdmin, auth.RoleAuditor, auth.RoleWriter, auth.RoleViewer:
		return true
	}
	return false
}

func (s *Server) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleWriter
	}
	if req.Name == "" || !validRole(req.Role) {
		http.Error(w, "name is required and role must be Admin|Auditor|Writer|Viewer", http.StatusBadRequest)
		return
	}
	id := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO service_accounts (id, org_id, name, role) VALUES ($1, $2, $3, $4)`,
		id, p.OrgID, req.Name, req.Role); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": id, "name": req.Name, "role": req.Role})
}

func (s *Server) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT sa.id, sa.name, sa.role, sa.enabled, sa.created_at,
		        count(k.id) FILTER (WHERE k.revoked_at IS NULL) AS active_keys
		 FROM service_accounts sa LEFT JOIN service_account_keys k ON k.service_account_id = sa.id
		 WHERE sa.org_id = $1 GROUP BY sa.id ORDER BY sa.created_at`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, role string
		var enabled bool
		var created time.Time
		var activeKeys int
		if err := rows.Scan(&id, &name, &role, &enabled, &created, &activeKeys); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "role": role, "enabled": enabled, "active_keys": activeKeys, "created_at": created.UTC().Format(time.RFC3339)})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleIssueServiceAccountKey(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	saID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid service account id", http.StatusBadRequest)
		return
	}
	var req struct {
		Label        string `json:"label"`
		ExpiresHours int    `json:"expires_hours"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Ownership check (org-scoped).
	var exists bool
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id = $1 AND org_id = $2)`, saID, p.OrgID).Scan(&exists); err != nil {
		internalError(w, err)
		return
	}
	if !exists {
		http.Error(w, "service account not found", http.StatusNotFound)
		return
	}

	full, prefix, secret, err := generateAPIKey()
	if err != nil {
		internalError(w, err)
		return
	}
	hash, err := crypto.HashPassword(secret)
	if err != nil {
		internalError(w, err)
		return
	}
	var expiresAt *time.Time
	if req.ExpiresHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresHours) * time.Hour)
		expiresAt = &t
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO service_account_keys (service_account_id, prefix, key_hash, label, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`, saID, prefix, hash, req.Label, expiresAt); err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// The full key is returned ONCE and never retrievable again.
	json.NewEncoder(w).Encode(map[string]any{"api_key": full, "prefix": prefix, "expires_at": expiresAt})
}

func (s *Server) handleRevokeServiceAccountKey(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	saID, err1 := uuid.Parse(r.PathValue("id"))
	keyID, err2 := uuid.Parse(r.PathValue("keyId"))
	if err1 != nil || err2 != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE service_account_keys k SET revoked_at = now()
		 FROM service_accounts sa
		 WHERE k.id = $1 AND k.service_account_id = sa.id AND sa.id = $2 AND sa.org_id = $3 AND k.revoked_at IS NULL`,
		keyID, saID, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "key not found or already revoked", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"revoked"}`))
}
