package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/db"
	"fides/pkg/models"
)

// providerDefaults returns the well-known OAuth endpoints and scope for a
// provider, used when the tenant config leaves them blank.
func providerDefaults(provider string) (authURL, tokenURL, userInfoURL, scope string) {
	switch provider {
	case "github":
		return "https://github.com/login/oauth/authorize",
			"https://github.com/login/oauth/access_token",
			"https://api.github.com/user",
			"read:user user:email"
	case "gitlab":
		return "https://gitlab.com/oauth/authorize",
			"https://gitlab.com/oauth/token",
			"https://gitlab.com/api/v4/user",
			"read_user"
	case "google":
		return "https://accounts.google.com/o/oauth2/v2/auth",
			"https://oauth2.googleapis.com/token",
			"https://openidconnect.googleapis.com/v1/userinfo",
			"openid email profile"
	case "okta":
		return "https://okta.com/oauth2/v1/authorize",
			"https://okta.com/oauth2/v1/token",
			"https://okta.com/oauth2/v1/userinfo",
			"openid email profile groups"
	default:
		return "", "", "", "openid email"
	}
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "github"
	}
	// org_id selects which tenant's SSO configuration to use. This is the only
	// place an org_id is accepted from the client, and it is bound into a signed,
	// single-use state nonce — the resulting session's org comes from that state.
	orgID, err := uuid.Parse(r.URL.Query().Get("org_id"))
	if err != nil {
		http.Error(w, "valid org_id query parameter is required", http.StatusBadRequest)
		return
	}

	var authConfig models.TenantAuthConfig
	queryAuth := `SELECT client_id, COALESCE(auth_url, ''), redirect_uri, enabled FROM tenant_auth_configs WHERE org_id = $1 AND provider_name = $2 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryAuth, orgID, provider).Scan(&authConfig.ClientID, &authConfig.AuthURL, &authConfig.RedirectURI, &authConfig.Enabled)
	if err != nil {
		http.Error(w, "no SSO provider is configured for this organization", http.StatusBadRequest)
		return
	}
	if !authConfig.Enabled {
		http.Error(w, "auth provider disabled for tenant", http.StatusForbidden)
		return
	}

	authURL := authConfig.AuthURL
	defAuth, _, _, scope := providerDefaults(provider)
	if authURL == "" {
		authURL = defAuth
	}
	if authURL == "" {
		http.Error(w, "unknown auth provider", http.StatusBadRequest)
		return
	}

	state, err := s.States.New(orgID, provider, 10*time.Minute, time.Now())
	if err != nil {
		http.Error(w, "failed to initialize login", http.StatusInternalServerError)
		return
	}

	q := neturl.Values{}
	q.Set("client_id", authConfig.ClientID)
	q.Set("redirect_uri", authConfig.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusTemporaryRedirect)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// 1. Validate the single-use state nonce (CSRF / replay defense). The tenant
	// and provider come from the server-side state, never from the client.
	stateData, ok := s.States.Consume(stateParam, time.Now())
	if !ok {
		http.Error(w, "invalid or expired login state", http.StatusBadRequest)
		return
	}
	orgID := stateData.OrgID
	provider := stateData.Provider

	// 2. Load the tenant's provider configuration and resolve the client secret.
	var clientID, secretPath, tokenURL, userInfoURL, redirectURI string
	var enabled bool
	queryAuth := `SELECT client_id, client_secret_path, COALESCE(token_url, ''), COALESCE(userinfo_url, ''), redirect_uri, enabled
	              FROM tenant_auth_configs WHERE org_id = $1 AND provider_name = $2 LIMIT 1`
	if err := s.q(r.Context()).QueryRowContext(r.Context(), queryAuth, orgID, provider).Scan(&clientID, &secretPath, &tokenURL, &userInfoURL, &redirectURI, &enabled); err != nil || !enabled {
		http.Error(w, "SSO provider not available", http.StatusBadRequest)
		return
	}

	_, defToken, defUserInfo, _ := providerDefaults(provider)
	if tokenURL == "" {
		tokenURL = defToken
	}
	if userInfoURL == "" {
		userInfoURL = defUserInfo
	}

	clientSecret, err := s.Secrets.GetSecret(r.Context(), "", secretPath)
	if err != nil {
		log.Printf("auth callback: client secret unavailable for org %s provider %s", orgID, provider)
		http.Error(w, "server auth configuration error", http.StatusInternalServerError)
		return
	}

	// 3. Exchange the code for a token and fetch the user's identity.
	accessToken, err := auth.ExchangeCode(r.Context(), s.httpClient, auth.OAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		RedirectURI:  redirectURI,
	}, code)
	if err != nil {
		log.Printf("auth callback: token exchange failed: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	userInfo, err := auth.FetchUserInfo(r.Context(), s.httpClient, userInfoURL, accessToken)
	if err != nil || userInfo.Email == "" {
		log.Printf("auth callback: userinfo lookup failed: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// 4. Resolve the principal's role within the tenant.
	principal := auth.Principal{OrgID: orgID, Email: userInfo.Email, Role: auth.RoleViewer, Kind: "session"}
	var userID uuid.UUID
	var role string
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT id, role FROM users WHERE org_id = $1 AND email = $2 LIMIT 1`, orgID, userInfo.Email,
	).Scan(&userID, &role); err == nil {
		principal.UserID = userID
		principal.Role = role
	} else if len(userInfo.Groups) > 0 {
		// Fall back to an SSO group → role mapping.
		var mappedRole string
		if err := s.q(r.Context()).QueryRowContext(r.Context(),
			`SELECT role FROM sso_group_mappings WHERE org_id = $1 AND external_group = ANY($2) LIMIT 1`,
			orgID, pq.Array(userInfo.Groups),
		).Scan(&mappedRole); err == nil {
			principal.Role = mappedRole
		}
	}

	// 5. Establish the session and set a hardened cookie.
	sessionToken, err := s.Sessions.Create(principal, 12*time.Hour, time.Now())
	if err != nil {
		http.Error(w, "failed to establish session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})

	http.Redirect(w, r, "/?login=success", http.StatusTemporaryRedirect)
}

type localLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// portalTenant returns the tenant for portal/basic auth. The org MUST be
// configured via FIDES_API_ORG_ID — there is no hardcoded default (H2/IDOR).
func portalTenant() (uuid.UUID, bool) {
	id, err := uuid.Parse(os.Getenv("FIDES_API_ORG_ID"))
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

// constantTimeEquals compares two strings without leaking length-independent
// timing, used for credential checks.
func constantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// resolvePortalPrincipal builds the principal for an authenticated portal admin.
// The role is read from the user's DB record resolved WITHIN the tenant's org
// scope (so it is correct even when RLS is enabled). If the admin is not
// provisioned as a user, they retain the bootstrap Admin role implied by holding
// the configured PORTAL_PASSWORD secret.
// localUserLogin verifies an email/password against the users table (per-user
// local login). Returns false if the user has no password set or it mismatches.
func (s *Server) localUserLogin(ctx context.Context, orgID uuid.UUID, email, password string) (auth.Principal, bool) {
	var p auth.Principal
	if s.DB == nil {
		return p, false
	}
	var uid uuid.UUID
	var role, hash string
	err := db.WithOrgScope(ctx, s.DB, orgID.String(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT id, role, COALESCE(password_hash, '') FROM users WHERE org_id = $1 AND email = $2 LIMIT 1`,
			orgID, email).Scan(&uid, &role, &hash)
	})
	if err != nil || hash == "" {
		return p, false
	}
	if !crypto.VerifyPassword(password, hash) {
		return p, false
	}
	return auth.Principal{OrgID: orgID, UserID: uid, Email: email, Role: role, Kind: "session"}, true
}

func (s *Server) resolvePortalPrincipal(ctx context.Context, orgID uuid.UUID, email string) *auth.Principal {
	p := &auth.Principal{OrgID: orgID, Email: email, Role: auth.RoleAdmin, Kind: "session"}
	if s.DB != nil {
		_ = db.WithOrgScope(ctx, s.DB, orgID.String(), func(tx *sql.Tx) error {
			var id uuid.UUID
			var role string
			if err := tx.QueryRowContext(ctx,
				`SELECT id, role FROM users WHERE org_id = $1 AND email = $2 LIMIT 1`, orgID, email,
			).Scan(&id, &role); err != nil {
				return err
			}
			p.UserID = id
			p.Role = role
			return nil
		})
	}
	return p
}

func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	portalUser := os.Getenv("PORTAL_USERNAME")
	portalPass := os.Getenv("PORTAL_PASSWORD")
	portalConfigured := portalUser != "" && portalPass != ""

	var req localLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	orgID, tenantConfigured := portalTenant()

	// Two local-login paths: the shared portal-admin credential (env) and
	// per-user passwords on the users table. Both need a configured tenant to
	// build a principal.
	var principal auth.Principal
	authed := false

	if portalConfigured {
		// Both comparisons run regardless of username match (no timing leak).
		adminUser := constantTimeEquals(req.Username, portalUser)
		adminPass := constantTimeEquals(req.Password, portalPass)
		if adminUser && adminPass {
			if !tenantConfigured {
				http.Error(w, "portal tenant (FIDES_API_ORG_ID) is not configured", http.StatusServiceUnavailable)
				return
			}
			principal = *s.resolvePortalPrincipal(r.Context(), orgID, req.Username)
			authed = true
		}
	}

	if !authed && tenantConfigured {
		if p, ok := s.localUserLogin(r.Context(), orgID, req.Username, req.Password); ok {
			principal = p
			authed = true
		}
	}

	if !authed {
		if !portalConfigured && !tenantConfigured {
			http.Error(w, "local authentication is not configured", http.StatusForbidden)
			return
		}
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	sessionToken, err := s.Sessions.Create(principal, 12*time.Hour, time.Now())
	if err != nil {
		http.Error(w, "failed to establish session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
