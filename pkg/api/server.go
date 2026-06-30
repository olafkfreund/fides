package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fides/pkg/admission"
	"fides/pkg/ai"
	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/db"
	"fides/pkg/events"
	"fides/pkg/inbound"
	"fides/pkg/mcp"
	"fides/pkg/models"
	"fides/pkg/policy"
	"fides/pkg/servicenow"
	"fides/pkg/storage"
	"fides/pkg/telemetry"
	"fides/pkg/vault"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Server struct {
	DB           *sql.DB
	Storage      storage.StorageBackend
	PolicyEngine *policy.PolicyEngine
	LLM          ai.LLMClient
	Secrets      vault.SecretsProvider
	States       *auth.StateStore
	Sessions     *auth.SessionStore
	httpClient   *http.Client
}

func NewServer(db *sql.DB, store storage.StorageBackend, llm ai.LLMClient) *Server {
	telemetry.Instance.SetDB(db)
	return &Server{
		DB:           db,
		Storage:      store,
		PolicyEngine: policy.NewPolicyEngine(),
		LLM:          llm,
		Secrets:      vault.NewProvider(context.Background()),
		States:       auth.NewStateStore(),
		Sessions:     auth.NewSessionStore(),
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Organization API
	mux.HandleFunc("POST /api/v1/orgs", s.handleCreateOrg)
	mux.HandleFunc("GET /api/v1/orgs", s.handleListOrgs)

	// Flow API
	mux.HandleFunc("POST /api/v1/flows", s.handleCreateFlow)
	mux.HandleFunc("PUT /api/v1/flows", s.handleUpdateFlow)
	mux.HandleFunc("GET /api/v1/flows", s.handleListFlows)

	// Trail API
	mux.HandleFunc("POST /api/v1/trails", s.handleCreateTrail)
	mux.HandleFunc("GET /api/v1/trails/{id}/verify-chain", s.handleVerifyTrailChain)
	mux.HandleFunc("GET /api/v1/trails/{id}/audit-package", s.handleTrailAuditPackage)

	// Search / query + snapshot diff
	mux.HandleFunc("GET /api/v1/search/artifacts", s.handleSearchArtifacts)
	mux.HandleFunc("GET /api/v1/search/attestations", s.handleSearchAttestations)
	mux.HandleFunc("GET /api/v1/environments/{id}/snapshots/diff", s.handleSnapshotDiff)

	// Per-environment artifact allow-list (explicit approvals)
	mux.HandleFunc("GET /api/v1/environments/{id}/allowlist", s.handleListAllowlist)
	mux.HandleFunc("POST /api/v1/environments/{id}/allowlist", s.handleAddAllowlist)
	mux.HandleFunc("DELETE /api/v1/environments/{id}/allowlist/{sha}", s.handleRemoveAllowlist)

	// Artifact API
	mux.HandleFunc("POST /api/v1/artifacts", s.handleReportArtifact)
	mux.HandleFunc("GET /api/v1/artifacts", s.handleListArtifacts)

	// Attestation Type API
	mux.HandleFunc("POST /api/v1/attestation-types", s.handleCreateAttestationType)

	// Attestation API
	mux.HandleFunc("POST /api/v1/attestations", s.handleReportAttestation)

	// Snapshot API
	mux.HandleFunc("POST /api/v1/snapshots", s.handleReportSnapshot)

	// Compliance and Drift API
	mux.HandleFunc("GET /api/v1/compliance", s.handleCheckCompliance)
	mux.HandleFunc("GET /api/v1/environments", s.handleListEnvironments)
	mux.HandleFunc("GET /api/v1/environments/export", s.handleExportEnvironmentAudit)
	mux.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	mux.HandleFunc("POST /api/v1/policies", s.handleSavePolicy)
	mux.HandleFunc("GET /api/v1/ai-assessments", s.handleListAIAssessments)

	// Tenant Webhooks (signed outbound delivery)
	mux.HandleFunc("GET /api/v1/tenant/webhooks", s.handleListWebhooks)
	mux.HandleFunc("POST /api/v1/tenant/webhooks", s.handleSaveWebhook)

	// Tenant Git Providers (CI/CD commit-status gating)
	mux.HandleFunc("GET /api/v1/tenant/git-providers", s.handleListGitProviders)
	mux.HandleFunc("POST /api/v1/tenant/git-providers", s.handleSaveGitProvider)

	// Tenant ServiceNow settings (CMDB/ITOM/ITSM)
	mux.HandleFunc("GET /api/v1/tenant/servicenow", s.handleGetServiceNow)
	mux.HandleFunc("POST /api/v1/tenant/servicenow", s.handleSaveServiceNow)
	mux.HandleFunc("GET /api/v1/tenant/servicenow/events", s.handleServiceNowEvents)

	// ServiceNow admin UI: a Go-served page (the page shell is public; its API
	// calls are authenticated by the session cookie, like the rest of the portal).
	mux.HandleFunc("GET /servicenow", s.handleServiceNowAdminPage)

	// ITSM change-control gate: fetch a ServiceNow change request and record a
	// servicenow-change attestation evaluated against its jq rules.
	mux.HandleFunc("POST /api/v1/servicenow/change-check", s.handleServiceNowChangeCheck)

	// Inbound CI/CD webhooks: auto-create a trail from a signed push event.
	// Public: authenticated by the provider's HMAC/token signature, not a bearer.
	mux.HandleFunc("POST /api/v1/webhooks/{provider}", s.handleInboundWebhook)

	// ServiceNow read/action endpoints (backing the MCP tools)
	mux.HandleFunc("GET /api/v1/servicenow/change-status", s.handleServiceNowChangeStatus)
	mux.HandleFunc("POST /api/v1/servicenow/incident", s.handleServiceNowCreateIncident)
	mux.HandleFunc("GET /api/v1/servicenow/cmdb", s.handleServiceNowSearchCMDB)

	// Kubernetes ValidatingAdmissionWebhook (deploy-time gate). Public: the API
	// server authenticates via mTLS (configure a CA bundle + NetworkPolicy).
	mux.HandleFunc("POST /api/v1/admission/validate", s.handleAdmissionValidate)

	// Environment MCP Connections API
	mux.HandleFunc("GET /api/v1/environments/mcp", s.handleListEnvironmentMCPServers)
	mux.HandleFunc("POST /api/v1/environments/mcp", s.handleSaveEnvironmentMCPServer)
	mux.HandleFunc("POST /api/v1/environments/mcp/query", s.handleQueryEnvironmentMCPServer)
	mux.HandleFunc("POST /api/v1/environments/mcp/verify", s.handleVerifyEnvironmentCompliance)

	// Tenant Settings & SSO APIs
	mux.HandleFunc("GET /api/v1/tenant/settings", s.handleGetTenantSettings)
	mux.HandleFunc("POST /api/v1/tenant/settings", s.handleSaveTenantSettings)
	mux.HandleFunc("GET /api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("GET /api/v1/auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /api/v1/auth/local-login", s.handleLocalLogin)

	// User Management and SSO group mappings API
	mux.HandleFunc("GET /api/v1/tenant/users", s.handleListUsers)
	mux.HandleFunc("POST /api/v1/tenant/users", s.handleSaveUser)
	mux.HandleFunc("POST /api/v1/tenant/users/{id}/password", s.handleSetUserPassword)

	// Service accounts + API keys (machine-to-machine auth, rotation/revocation)
	mux.HandleFunc("GET /api/v1/tenant/service-accounts", s.handleListServiceAccounts)
	mux.HandleFunc("POST /api/v1/tenant/service-accounts", s.handleCreateServiceAccount)
	mux.HandleFunc("POST /api/v1/tenant/service-accounts/{id}/keys", s.handleIssueServiceAccountKey)
	mux.HandleFunc("DELETE /api/v1/tenant/service-accounts/{id}/keys/{keyId}", s.handleRevokeServiceAccountKey)
	mux.HandleFunc("GET /api/v1/tenant/group-mappings", s.handleListGroupMappings)
	mux.HandleFunc("POST /api/v1/tenant/group-mappings", s.handleSaveGroupMapping)

	// Swagger API Docs
	mux.HandleFunc("GET /api/v1/swagger.json", s.handleSwaggerJSON)
	mux.HandleFunc("GET /swagger", s.handleSwaggerUI)

	// Telemetry metrics
	mux.HandleFunc("GET /metrics", telemetry.Instance.PrometheusExporter)
	mux.HandleFunc("GET /api/v1/telemetry/metrics", telemetry.Instance.JSONExporter)

	// AI Policy Wizard & Chat APIs
	mux.HandleFunc("POST /api/v1/ai/generate-policy", s.handleAIGeneratePolicy)
	mux.HandleFunc("POST /api/v1/ai/chat", s.handleAIChat)

	// System Status
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// LLM Documentation Endpoints
	mux.HandleFunc("GET /llms.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, "./web/llms.txt")
	})
	mux.HandleFunc("GET /llms-full.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, "./web/llms-full.txt")
	})

	// Static Web Portal Interface
	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("GET /", fs)

	return securityHeaders(limitBody(s.authMiddleware(telemetry.Middleware(mux))))
}

// maxRequestBody caps request body size to mitigate memory-exhaustion DoS.
// It is generous enough to accommodate multipart evidence uploads.
const maxRequestBody = 64 << 20 // 64 MiB

// limitBody wraps every request body in http.MaxBytesReader.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// isPublicPath reports whether a request path is reachable without authentication.
// Everything else under /api/v1 requires a valid bearer token.
func isPublicPath(path string) bool {
	publicExact := map[string]bool{
		"/healthz":                 true,
		"/metrics":                 true,
		"/api/v1/auth/login":       true,
		"/api/v1/auth/callback":    true,
		"/api/v1/auth/local-login": true,
		"/api/v1/swagger.json":     true,
		"/swagger":                 true,
		"/llms.txt":                true,
		"/llms-full.txt":           true,
		// K8s admission webhook: authenticated by the API server via mTLS, not a token.
		"/api/v1/admission/validate": true,
	}
	if publicExact[path] {
		return true
	}
	// Inbound webhooks authenticate via the provider's HMAC/token signature.
	if strings.HasPrefix(path, "/api/v1/webhooks/") {
		return true
	}
	// The static web portal and its assets are public; the API surface is not.
	return !strings.HasPrefix(path, "/api/v1/")
}

const sessionCookieName = "fides_session"

// authMiddleware authenticates the API surface and attaches a Principal to the
// request context. Two credential types are accepted:
//   - an interactive SSO session cookie (set by the OAuth callback), or
//   - the static service bearer token FIDES_API_TOKEN (used by the CLI/MCP),
//     whose tenant scope is fixed by FIDES_API_ORG_ID.
//
// The Principal's OrgID is the ONLY source of tenant scoping downstream; handlers
// must never trust an org_id from the request body or query (see H2 / IDOR).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		portalUser := os.Getenv("PORTAL_USERNAME")
		portalPass := os.Getenv("PORTAL_PASSWORD")

		// System paths bypass authentication
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" || r.URL.Path == "/swagger" || r.URL.Path == "/api/v1/swagger.json" || r.URL.Path == "/llms.txt" || r.URL.Path == "/llms-full.txt" {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Basic Auth check if portal credentials are set
		if portalUser != "" && portalPass != "" {
			username, password, ok := r.BasicAuth()
			if ok && constantTimeEquals(username, portalUser) && constantTimeEquals(password, portalPass) {
				orgID, configured := portalTenant()
				if !configured {
					http.Error(w, "portal tenant (FIDES_API_ORG_ID) is not configured", http.StatusServiceUnavailable)
					return
				}
				principal := s.resolvePortalPrincipal(r.Context(), orgID, username)
				s.serveAuthenticated(w, r, principal, next)
				return
			}
		}

		// 2. Standard public path bypass (static files and public auth routes)
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Interactive session cookie.
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if p, ok := s.Sessions.Get(c.Value, time.Now()); ok {
				s.serveAuthenticated(w, r, &p, next)
				return
			}
		}

		// 4. Static service bearer token.
		// The env service token gates whether API auth is configured at all.
		expected := os.Getenv("FIDES_API_TOKEN")
		if expected == "" {
			http.Error(w, "API authentication is not configured on the server", http.StatusServiceUnavailable)
			return
		}

		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		presented := strings.TrimPrefix(authz, prefix)

		// 1) Static env service token (constant-time compare; tenant from FIDES_API_ORG_ID).
		if subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1 {
			orgID, err := uuid.Parse(os.Getenv("FIDES_API_ORG_ID"))
			if err != nil {
				http.Error(w, "service token tenant (FIDES_API_ORG_ID) is not configured", http.StatusServiceUnavailable)
				return
			}
			s.serveAuthenticated(w, r, &auth.Principal{OrgID: orgID, Role: auth.RoleAdmin, Kind: "service"}, next)
			return
		}

		// 2) Per-tenant service-account API key.
		if p := s.authServiceAccountKey(r.Context(), presented); p != nil {
			s.serveAuthenticated(w, r, p, next)
			return
		}

		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	})
}

// serveAuthenticated attaches the principal to the request context and, when
// RLS scoping is enabled (FIDES_RLS_ENABLED=true), pins a tenant-scoped DB
// connection (app.current_org set to the principal's org) into the context so
// handlers' s.q(ctx) calls are isolated by Postgres RLS. The connection is
// released after the handler returns.
func (s *Server) serveAuthenticated(w http.ResponseWriter, r *http.Request, p *auth.Principal, next http.Handler) {
	ctx := auth.WithPrincipal(r.Context(), p)

	if os.Getenv("FIDES_RLS_ENABLED") == "true" && s.DB != nil {
		conn, release, err := db.ScopedConn(ctx, s.DB, p.OrgID.String())
		if err != nil {
			internalError(w, err)
			return
		}
		defer release()
		ctx = db.WithQuerier(ctx, conn)
	}

	next.ServeHTTP(w, r.WithContext(ctx))
}

// q returns the tenant-scoped Querier for this request when RLS scoping is
// active, otherwise the unscoped connection pool. This makes handler queries
// behavior-identical when RLS is disabled.
func (s *Server) q(ctx context.Context) db.Querier {
	if scoped, ok := db.QuerierFromContext(ctx); ok {
		return scoped
	}
	return s.DB
}

// principalOrg returns the authenticated tenant for the request. Handlers use
// this as the sole source of org scoping. The bool is false only if the request
// somehow bypassed authMiddleware (defensive).
func principalOrg(r *http.Request) (uuid.UUID, bool) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		return uuid.UUID{}, false
	}
	return p.OrgID, true
}

// securityHeaders adds baseline hardening headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// internalError logs the underlying error server-side and returns a generic
// message to the client, so DB/driver/internal details are not leaked (M3).
func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// badRequest returns a generic 400 without echoing parse/validation detail.
func badRequest(w http.ResponseWriter, err error) {
	if err != nil {
		log.Printf("bad request: %v", err)
	}
	http.Error(w, "invalid request", http.StatusBadRequest)
}

// Helper JSONB conversion
func marshalJSONB(m map[string]string) []byte {
	if m == nil {
		return []byte("{}")
	}
	data, _ := json.Marshal(m)
	return data
}

func unmarshalJSONB(data []byte) map[string]string {
	m := make(map[string]string)
	if len(data) > 0 {
		json.Unmarshal(data, &m)
	}
	return m
}

// REST Handlers

type createOrgReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req createOrgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	org := &models.Organization{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
	}

	query := `INSERT INTO organizations (id, name, description, created_at) VALUES ($1, $2, $3, $4)`
	_, err := s.q(r.Context()).ExecContext(r.Context(), query, org.ID, org.Name, org.Description, org.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	query := `SELECT id, name, COALESCE(description, '') AS description, created_at FROM organizations ORDER BY name`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	var list []*models.Organization
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Description, &o.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &o)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type createFlowReq struct {
	OrgID       string            `json:"org_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Tags        map[string]string `json:"tags"`
}

func (s *Server) handleCreateFlow(w http.ResponseWriter, r *http.Request) {
	var req createFlowReq
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

	flow := &models.Flow{
		ID:          uuid.New(),
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, flow.ID, flow.OrgID, flow.Name, flow.Description, marshalJSONB(flow.Tags), flow.CreatedAt, flow.UpdatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

type updateFlowReq struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Tags        map[string]string `json:"tags"`
}

func (s *Server) handleUpdateFlow(w http.ResponseWriter, r *http.Request) {
	var req updateFlowReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	flowID, err := uuid.Parse(req.ID)
	if err != nil {
		http.Error(w, "invalid flow id", http.StatusBadRequest)
		return
	}

	query := `UPDATE flows SET name = $1, description = $2, tags = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, req.Name, req.Description, marshalJSONB(req.Tags), flowID)
	if err != nil {
		internalError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := `SELECT id, org_id, name, COALESCE(description, '') AS description, tags, created_at, updated_at FROM flows WHERE org_id = $1 ORDER BY name`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	var list []*models.Flow
	for rows.Next() {
		var f models.Flow
		var tagsBytes []byte
		if err := rows.Scan(&f.ID, &f.OrgID, &f.Name, &f.Description, &tagsBytes, &f.CreatedAt, &f.UpdatedAt); err != nil {
			internalError(w, err)
			return
		}
		f.Tags = unmarshalJSONB(tagsBytes)
		list = append(list, &f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type createTrailReq struct {
	FlowID        string            `json:"flow_id"`
	Name          string            `json:"name"`
	GitRepository string            `json:"git_repository"`
	GitCommit     string            `json:"git_commit"`
	GitBranch     string            `json:"git_branch"`
	GitMessage    string            `json:"git_message"`
	Tags          map[string]string `json:"tags"`
}

func (s *Server) handleCreateTrail(w http.ResponseWriter, r *http.Request) {
	var req createTrailReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	flowID, err := uuid.Parse(req.FlowID)
	if err != nil {
		http.Error(w, "invalid flow_id", http.StatusBadRequest)
		return
	}

	trail := &models.Trail{
		ID:            uuid.New(),
		FlowID:        flowID,
		Name:          req.Name,
		GitRepository: req.GitRepository,
		GitCommit:     req.GitCommit,
		GitBranch:     req.GitBranch,
		GitMessage:    req.GitMessage,
		Tags:          req.Tags,
		CreatedAt:     time.Now(),
	}

	query := `INSERT INTO trails (id, flow_id, name, git_repository, git_commit, git_branch, git_message, tags, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, trail.ID, trail.FlowID, trail.Name, trail.GitRepository, trail.GitCommit, trail.GitBranch, trail.GitMessage, marshalJSONB(trail.Tags), trail.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(trail)
}

type reportArtifactReq struct {
	OrgID   string            `json:"org_id"`
	TrailID string            `json:"trail_id"`
	SHA256  string            `json:"sha256"`
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Tags    map[string]string `json:"tags"`
}

func (s *Server) handleReportArtifact(w http.ResponseWriter, r *http.Request) {
	var req reportArtifactReq
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

	var trailID *uuid.UUID
	if req.TrailID != "" {
		tID, err := uuid.Parse(req.TrailID)
		if err != nil {
			http.Error(w, "invalid trail_id", http.StatusBadRequest)
			return
		}
		trailID = &tID
	}

	artifact := &models.Artifact{
		SHA256:    req.SHA256,
		OrgID:     orgID,
		TrailID:   trailID,
		Name:      req.Name,
		Type:      req.Type,
		Tags:      req.Tags,
		CreatedAt: time.Now(),
	}

	query := `INSERT INTO artifacts (sha256, org_id, trail_id, name, type, tags, created_at) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          ON CONFLICT (sha256) DO UPDATE SET trail_id = EXCLUDED.trail_id`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, artifact.SHA256, artifact.OrgID, artifact.TrailID, artifact.Name, artifact.Type, marshalJSONB(artifact.Tags), artifact.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(artifact)
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Joining trail name for simple UI rendering
	query := `SELECT a.sha256, a.org_id, a.trail_id, a.name, a.type, a.tags, a.created_at, COALESCE(t.name, '')
	          FROM artifacts a
	          LEFT JOIN trails t ON a.trail_id = t.id
	          WHERE a.org_id = $1
	          ORDER BY a.created_at DESC`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	// Struct representation specifically decorated for UI rendering
	type ArtifactView struct {
		models.Artifact
		TrailName  string        `json:"trail_name"`
		SBOMStatus string        `json:"sbom_status"`
		SBOM       []interface{} `json:"sbom"`
	}

	var list []*ArtifactView
	for rows.Next() {
		var av ArtifactView
		var tagsBytes []byte
		if err := rows.Scan(&av.SHA256, &av.OrgID, &av.TrailID, &av.Name, &av.Type, &tagsBytes, &av.CreatedAt, &av.TrailName); err != nil {
			internalError(w, err)
			return
		}
		av.Tags = unmarshalJSONB(tagsBytes)

		// Fetch actual SBOM from database attestations if present
		var payloadBytes []byte
		var isCompliant bool
		querySBOM := `SELECT payload, is_compliant FROM attestations WHERE artifact_sha256 = $1 AND (name = 'sbom' OR type_name = 'sbom' OR type_name = 'sbom-scan') LIMIT 1`
		err = s.q(r.Context()).QueryRowContext(r.Context(), querySBOM, av.SHA256).Scan(&payloadBytes, &isCompliant)
		if err == nil {
			if isCompliant {
				av.SBOMStatus = "Compliant"
			} else {
				av.SBOMStatus = "Non-Compliant"
			}

			// Try to unmarshal payload as a list of packages
			var packages []interface{}
			if errUnmarshal := json.Unmarshal(payloadBytes, &packages); errUnmarshal == nil {
				av.SBOM = packages
			} else {
				// If not a list, maybe it's an object with "packages" or "components" key
				var obj map[string]interface{}
				if errUnmarshalObj := json.Unmarshal(payloadBytes, &obj); errUnmarshalObj == nil {
					if pkgs, ok := obj["packages"]; ok {
						if pkgsList, ok := pkgs.([]interface{}); ok {
							av.SBOM = pkgsList
						}
					} else if comps, ok := obj["components"]; ok {
						if compsList, ok := comps.([]interface{}); ok {
							av.SBOM = compsList
						}
					} else {
						// Otherwise, just wrap the object in a slice
						av.SBOM = []interface{}{obj}
					}
				} else {
					av.SBOM = []interface{}{}
				}
			}
		} else {
			av.SBOMStatus = "Pending"
			av.SBOM = []interface{}{}
		}
		list = append(list, &av)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type createAttestationTypeReq struct {
	OrgID       string   `json:"org_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
	JQRules     []string `json:"jq_rules"`
}

func (s *Server) handleCreateAttestationType(w http.ResponseWriter, r *http.Request) {
	var req createAttestationTypeReq
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

	attType := &models.AttestationType{
		ID:          uuid.New(),
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		Schema:      req.Schema,
		JQRules:     req.JQRules,
		CreatedAt:   time.Now(),
	}

	query := `INSERT INTO attestation_types (id, org_id, name, description, schema, jq_rules, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, attType.ID, attType.OrgID, attType.Name, attType.Description, attType.Schema, pq.Array(attType.JQRules), attType.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(attType)
}

type reportAttestationReq struct {
	TrailID             string `json:"trail_id"`
	ArtifactSHA256      string `json:"artifact_sha256"`
	Name                string `json:"name"` // unit-tests, sbom, snyk-scan
	TypeName            string `json:"type_name"`
	Payload             string `json:"payload"` // JSON string
	SignedBy            string `json:"signed_by"`
	Signature           string `json:"signature"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	ManifestationReason string `json:"manifestation_reason"`
}

func (s *Server) handleReportAttestation(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")

	var req reportAttestationReq
	var fileReaders []io.Reader
	var fileNames []string

	if contentType == "application/json" || contentType == "" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, err)
			return
		}
	} else {
		// #nosec G120 -- bounded to 32MB in-memory; total request body is capped by the limitBody middleware
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			badRequest(w, err)
			return
		}

		req.TrailID = r.FormValue("trail_id")
		req.ArtifactSHA256 = r.FormValue("artifact_sha256")
		req.Name = r.FormValue("name")
		req.TypeName = r.FormValue("type_name")
		req.Payload = r.FormValue("payload")
		req.SignedBy = r.FormValue("signed_by")
		req.Signature = r.FormValue("signature")
		req.SignatureAlgorithm = r.FormValue("signature_algorithm")
		req.ManifestationReason = r.FormValue("manifestation_reason")

		files := r.MultipartForm.File["attachments"]
		for _, fHeaders := range files {
			f, err := fHeaders.Open()
			if err != nil {
				internalError(w, err)
				return
			}
			defer f.Close()
			fileReaders = append(fileReaders, f)
			fileNames = append(fileNames, fHeaders.Filename)
		}
	}

	// Payload Decryption Step
	isEncrypted := r.FormValue("encrypted") == "true" || r.Header.Get("X-Fides-Encrypted") == "true"
	if isEncrypted {
		encryptionKey := os.Getenv("FIDES_ENCRYPTION_KEY")
		if encryptionKey == "" {
			http.Error(w, "server error: decryption key not configured on server", http.StatusInternalServerError)
			return
		}
		key, err := crypto.DeriveKey(encryptionKey)
		if err != nil {
			http.Error(w, "server error: invalid decryption key configured", http.StatusInternalServerError)
			return
		}
		decrypted, err := crypto.Decrypt(req.Payload, key)
		if err != nil {
			http.Error(w, "decryption failure: payload could not be decrypted", http.StatusBadRequest)
			return
		}
		req.Payload = string(decrypted)
	}

	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		http.Error(w, "invalid trail_id", http.StatusBadRequest)
		return
	}

	var artifactSHA *string
	if req.ArtifactSHA256 != "" {
		artifactSHA = &req.ArtifactSHA256
	}

	// Fetch rules for verification
	var rules []string
	queryType := `SELECT jq_rules FROM attestation_types WHERE name = $1 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryType, req.TypeName).Scan(pq.Array(&rules))
	if err != nil && err != sql.ErrNoRows {
		internalError(w, err)
		return
	}

	// Evaluate JQ rules
	isCompliant := true
	if len(rules) > 0 {
		ok, failedRules, err := s.PolicyEngine.EvaluateAttestation(req.Payload, rules)
		if err != nil {
			internalError(w, err)
			return
		}
		if !ok {
			isCompliant = false
			log.Printf("Compliance check failed for rules: %v", failedRules)
		}
	}

	attestation := &models.Attestation{
		ID:                  uuid.New(),
		TrailID:             trailID,
		ArtifactSHA256:      artifactSHA,
		Name:                req.Name,
		TypeName:            req.TypeName,
		Payload:             req.Payload,
		IsCompliant:         isCompliant,
		SignedBy:            req.SignedBy,
		Signature:           req.Signature,
		SignatureAlgorithm:  req.SignatureAlgorithm,
		ManifestationReason: req.ManifestationReason,
		CreatedAt:           time.Now(),
	}

	contentHash, prevHash, err := s.attestationChain(r.Context(), attestation.TrailID, attestation.Name, attestation.TypeName, attestation.Payload, attestation.IsCompliant)
	if err != nil {
		internalError(w, err)
		return
	}
	queryInsert := `INSERT INTO attestations (id, trail_id, artifact_sha256, name, type_name, payload, is_compliant, signed_by, signature, signature_algorithm, manifestation_reason, content_hash, prev_hash, created_at)
	                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), queryInsert, attestation.ID, attestation.TrailID, attestation.ArtifactSHA256, attestation.Name, attestation.TypeName, attestation.Payload, attestation.IsCompliant, attestation.SignedBy, attestation.Signature, attestation.SignatureAlgorithm, attestation.ManifestationReason, contentHash, prevHash, attestation.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	// Emit a compliance.evaluated event so CI/CD commit-status gates can publish
	// the verdict to the trail's commit (opt-in via FIDES_EVENTS_ENABLED).
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if orgID, ok := principalOrg(r); ok {
			if err := events.Enqueue(r.Context(), s.DB, orgID, "compliance.evaluated", map[string]any{
				"trail_id":    attestation.TrailID.String(),
				"attestation": attestation.Name,
				"compliant":   attestation.IsCompliant,
			}); err != nil {
				log.Printf("failed to enqueue compliance.evaluated event: %v", err)
			}
		}
	}

	// Upload attachments to Object Store and save mapping
	for i, reader := range fileReaders {
		// Use only the base name of the client-supplied filename to prevent
		// path traversal (e.g. "../../etc/passwd") in the storage key.
		safeName := filepath.Base(filepath.Clean("/" + fileNames[i]))
		key := fmt.Sprintf("%s/%s", attestation.ID, safeName)
		bucket := os.Getenv("AWS_S3_BUCKET")
		if bucket == "" {
			bucket = "fides-evidence"
		}
		path, err := s.Storage.Upload(r.Context(), bucket, key, reader, "application/octet-stream")
		if err != nil {
			internalError(w, err)
			return
		}

		attachmentID := uuid.New()
		queryAttach := `INSERT INTO evidence_attachments (id, attestation_id, file_name, file_size, file_hash, storage_path, content_type, created_at)
		                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err = s.q(r.Context()).ExecContext(r.Context(), queryAttach, attachmentID, attestation.ID, fileNames[i], 0, "hash", path, "application/octet-stream", time.Now())
		if err != nil {
			log.Printf("Failed to record attachment in DB: %v", err)
		}
	}

	// Trigger async LLM Evaluation if provider config exists
	if s.LLM != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			assessment, score, err := s.LLM.EvaluateAttestation(ctx, attestation.Name, attestation.TypeName, attestation.Payload)
			if err != nil {
				log.Printf("LLM Audit error: %v", err)
				return
			}

			// Save LLM assessment findings
			assID := uuid.New()
			queryAss := `INSERT INTO llm_assessments (id, attestation_id, model_provider, model_name, prompt_template_version, assessment_raw, compliance_score, findings, created_at)
			             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
			_, err = s.q(ctx).ExecContext(ctx, queryAss, assID, attestation.ID, "local", "llama3", "v1", assessment, score, "[]", time.Now())
			if err != nil {
				log.Printf("Failed to write LLM assessment to DB: %v", err)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(attestation)
}

type reportSnapshotReq struct {
	EnvironmentID string `json:"environment_id"`
	Artifacts     []struct {
		SHA256      string `json:"sha256"`
		ServiceName string `json:"service_name"`
	} `json:"artifacts"`
}

type snapshotReportResponse struct {
	SnapshotID uuid.UUID `json:"snapshot_id"`
	Compliant  bool      `json:"compliant"`
	Drifts     []string  `json:"drifts"`
	Shadows    []string  `json:"shadow_changes"`
}

func (s *Server) handleReportSnapshot(w http.ResponseWriter, r *http.Request) {
	var req reportSnapshotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}

	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback()

	snapshotID := uuid.New()
	querySnap := `INSERT INTO environment_snapshots (id, environment_id, created_at) VALUES ($1, $2, $3)`
	_, err = tx.ExecContext(r.Context(), querySnap, snapshotID, envID, time.Now())
	if err != nil {
		internalError(w, err)
		return
	}

	var drifts []string
	var shadows []string
	var services []map[string]any // running services, for the CMDB sync event
	isCompliant := true

	for _, a := range req.Artifacts {
		// Verify artifact provenance
		var dbSHA, dbTrailID string
		queryArt := `SELECT sha256, trail_id FROM artifacts WHERE sha256 = $1 LIMIT 1`
		err := tx.QueryRowContext(r.Context(), queryArt, a.SHA256).Scan(&dbSHA, &dbTrailID)

		if err == sql.ErrNoRows {
			// Shadow deployment: digest is running but not registered in database
			shadows = append(shadows, fmt.Sprintf("service %s running unregistered digest %s", a.ServiceName, a.SHA256))
			services = append(services, map[string]any{"service": a.ServiceName, "digest": a.SHA256, "registered": false})
			isCompliant = false

			// Insert runtime record anyway
			saID := uuid.New()
			querySA := `INSERT INTO snapshot_artifacts (id, snapshot_id, artifact_sha256, service_name, runtime_digest, started_at)
			            VALUES ($1, $2, NULL, $3, $4, $5)`
			tx.ExecContext(r.Context(), querySA, saID, snapshotID, a.ServiceName, a.SHA256, time.Now())
			continue
		} else if err != nil {
			internalError(w, err)
			return
		}

		services = append(services, map[string]any{"service": a.ServiceName, "digest": a.SHA256, "registered": true})

		// Insert valid trace record
		saID := uuid.New()
		querySA := `INSERT INTO snapshot_artifacts (id, snapshot_id, artifact_sha256, service_name, runtime_digest, started_at)
		            VALUES ($1, $2, $3, $4, $5, $6)`
		_, err = tx.ExecContext(r.Context(), querySA, saID, snapshotID, dbSHA, a.ServiceName, a.SHA256, time.Now())
		if err != nil {
			internalError(w, err)
			return
		}

		// Check for drift (failing compliance controls in build trail)
		queryAtt := `SELECT name, is_compliant FROM attestations WHERE trail_id = $1`
		rows, err := tx.QueryContext(r.Context(), queryAtt, dbTrailID)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var attName string
			var compliant bool
			if err := rows.Scan(&attName, &compliant); err != nil {
				internalError(w, err)
				return
			}
			if !compliant {
				drifts = append(drifts, fmt.Sprintf("service %s running drifted artifact %s (failing control: %s)", a.ServiceName, a.SHA256, attName))
				isCompliant = false
			}
		}
	}

	if err := tx.Commit(); err != nil {
		internalError(w, err)
		return
	}

	// Emit an integration event for downstream gates/alerts (opt-in via
	// FIDES_EVENTS_ENABLED). Best-effort: the snapshot is already committed, so a
	// failure here must not fail the request.
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && (len(shadows) > 0 || len(drifts) > 0) {
		if orgID, ok := principalOrg(r); ok {
			payload := map[string]any{
				"environment_id": envID.String(),
				"snapshot_id":    snapshotID.String(),
				"compliant":      isCompliant,
				"shadows":        shadows,
				"drifts":         drifts,
			}
			if err := events.Enqueue(r.Context(), s.DB, orgID, "snapshot.noncompliant", payload); err != nil {
				log.Printf("failed to enqueue snapshot.noncompliant event: %v", err)
			}
		}
	}

	// Emit a snapshot.reported event on every snapshot (CMDB sync consumes this).
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && len(services) > 0 {
		if orgID, ok := principalOrg(r); ok {
			if err := events.Enqueue(r.Context(), s.DB, orgID, "snapshot.reported", map[string]any{
				"environment": envID.String(),
				"services":    services,
			}); err != nil {
				log.Printf("failed to enqueue snapshot.reported event: %v", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(snapshotReportResponse{
		SnapshotID: snapshotID,
		Compliant:  isCompliant,
		Drifts:     drifts,
		Shadows:    shadows,
	})
}

func (s *Server) handleCheckCompliance(w http.ResponseWriter, r *http.Request) {
	sha := r.URL.Query().Get("sha256")
	if sha == "" {
		http.Error(w, "missing sha256 query param", http.StatusBadRequest)
		return
	}

	var name string
	var trailID sql.NullString
	queryArt := `SELECT name, trail_id FROM artifacts WHERE sha256 = $1 LIMIT 1`
	err := s.q(r.Context()).QueryRowContext(r.Context(), queryArt, sha).Scan(&name, &trailID)
	if err == sql.ErrNoRows {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}

	isCompliant := true
	var reasons []string

	if trailID.Valid && trailID.String != "" {
		queryAtt := `SELECT name, type_name, is_compliant FROM attestations WHERE trail_id = $1`
		rows, err := s.q(r.Context()).QueryContext(r.Context(), queryAtt, trailID.String)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var attName, typeName string
			var compliant bool
			if err := rows.Scan(&attName, &typeName, &compliant); err != nil {
				internalError(w, err)
				return
			}
			if !compliant {
				isCompliant = false
				reasons = append(reasons, fmt.Sprintf("Failing control: %s (Type: %s)", attName, typeName))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sha256":     sha,
		"name":       name,
		"compliant":  isCompliant,
		"violations": reasons,
	})
}

func (s *Server) handleListEnvironments(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	queryEnv := `SELECT id, name, type, COALESCE(description, '') AS description FROM environments WHERE org_id = $1`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), queryEnv, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	// Complete detailed Environment view model mapping to what frontend app.js expects
	type RuntimeArtifact struct {
		Service    string `json:"service"`
		SHA256     string `json:"sha256"`
		Registered bool   `json:"registered"`
		Name       string `json:"name"`
	}

	type EnvironmentView struct {
		ID            string            `json:"id"`
		Name          string            `json:"name"`
		Type          string            `json:"type"`
		Description   string            `json:"description"`
		LastSnapshot  string            `json:"lastSnapshot"`
		Running       []RuntimeArtifact `json:"running"`
		Drifts        []string          `json:"drifts"`
		ShadowChanges []string          `json:"shadowChanges"`
	}

	var list []*EnvironmentView
	for rows.Next() {
		var ev EnvironmentView
		if err := rows.Scan(&ev.ID, &ev.Name, &ev.Type, &ev.Description); err != nil {
			internalError(w, err)
			return
		}
		ev.LastSnapshot = "No snapshot reported yet"
		ev.Running = []RuntimeArtifact{}
		ev.Drifts = []string{}
		ev.ShadowChanges = []string{}

		// Fetch latest snapshot ID
		var latestSnapID string
		var snapTime time.Time
		querySnap := `SELECT id, created_at FROM environment_snapshots WHERE environment_id = $1 ORDER BY created_at DESC LIMIT 1`
		err = s.q(r.Context()).QueryRowContext(r.Context(), querySnap, ev.ID).Scan(&latestSnapID, &snapTime)

		if err == nil {
			ev.LastSnapshot = snapTime.Format("2006-01-02 15:04:05")

			// Query running artifacts in snapshot
			querySA := `SELECT sa.service_name, sa.runtime_digest, (sa.artifact_sha256 IS NOT NULL), COALESCE(a.name, '')
			            FROM snapshot_artifacts sa
			            LEFT JOIN artifacts a ON sa.artifact_sha256 = a.sha256
			            WHERE sa.snapshot_id = $1`
			saRows, err := s.q(r.Context()).QueryContext(r.Context(), querySA, latestSnapID)
			if err == nil {
				defer saRows.Close()
				for saRows.Next() {
					var ra RuntimeArtifact
					if err := saRows.Scan(&ra.Service, &ra.SHA256, &ra.Registered, &ra.Name); err == nil {
						ev.Running = append(ev.Running, ra)

						if !ra.Registered {
							ev.ShadowChanges = append(ev.ShadowChanges, fmt.Sprintf("service %s running unregistered digest %s", ra.Service, ra.SHA256))
						} else {
							// Check if registered artifact has drift (failing controls)
							var trailID sql.NullString
							s.q(r.Context()).QueryRowContext(r.Context(), "SELECT trail_id FROM artifacts WHERE sha256 = $1 LIMIT 1", ra.SHA256).Scan(&trailID)
							if trailID.Valid {
								var compliantCount, totalCount int
								s.q(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*), SUM(CASE WHEN is_compliant THEN 1 ELSE 0 END) FROM attestations WHERE trail_id = $1", trailID.String).Scan(&totalCount, &compliantCount)
								if totalCount > 0 && compliantCount < totalCount {
									ev.Drifts = append(ev.Drifts, fmt.Sprintf("service %s running drifted artifact %s (failing controls)", ra.Service, ra.SHA256))
								}
							}
						}
					}
				}
			}
		}
		list = append(list, &ev)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleExportEnvironmentAudit(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	envIDStr := r.URL.Query().Get("environment_id")
	if envIDStr == "" {
		http.Error(w, "missing environment_id parameter", http.StatusBadRequest)
		return
	}
	envID, err := uuid.Parse(envIDStr)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}

	queryEnv := `SELECT id, name, type, COALESCE(description, '') AS description FROM environments WHERE id = $1 AND org_id = $2`
	var id, name, envType, description string
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryEnv, envID, orgID).Scan(&id, &name, &envType, &description)
	if err != nil {
		http.Error(w, fmt.Sprintf("environment not found: %v", err), http.StatusNotFound)
		return
	}

	// Complete detailed Environment view model mapping
	type RuntimeArtifact struct {
		Service    string `json:"service"`
		SHA256     string `json:"sha256"`
		Registered bool   `json:"registered"`
		Name       string `json:"name"`
	}

	type EnvironmentView struct {
		ID            string            `json:"id"`
		Name          string            `json:"name"`
		Type          string            `json:"type"`
		Description   string            `json:"description"`
		LastSnapshot  string            `json:"lastSnapshot"`
		Running       []RuntimeArtifact `json:"running"`
		Drifts        []string          `json:"drifts"`
		ShadowChanges []string          `json:"shadowChanges"`
	}

	ev := EnvironmentView{
		ID:            id,
		Name:          name,
		Type:          envType,
		Description:   description,
		LastSnapshot:  "No snapshot reported yet",
		Running:       []RuntimeArtifact{},
		Drifts:        []string{},
		ShadowChanges: []string{},
	}

	// Fetch latest snapshot ID
	var latestSnapID string
	var snapTime time.Time
	querySnap := `SELECT id, created_at FROM environment_snapshots WHERE environment_id = $1 ORDER BY created_at DESC LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), querySnap, envID).Scan(&latestSnapID, &snapTime)

	if err == nil {
		ev.LastSnapshot = snapTime.Format("2006-01-02 15:04:05")

		// Query running artifacts in snapshot
		querySA := `SELECT sa.service_name, sa.runtime_digest, (sa.artifact_sha256 IS NOT NULL), COALESCE(a.name, '')
		            FROM snapshot_artifacts sa
		            LEFT JOIN artifacts a ON sa.artifact_sha256 = a.sha256
		            WHERE sa.snapshot_id = $1`
		saRows, err := s.q(r.Context()).QueryContext(r.Context(), querySA, latestSnapID)
		if err == nil {
			defer saRows.Close()
			for saRows.Next() {
				var ra RuntimeArtifact
				if err := saRows.Scan(&ra.Service, &ra.SHA256, &ra.Registered, &ra.Name); err == nil {
					ev.Running = append(ev.Running, ra)

					if !ra.Registered {
						ev.ShadowChanges = append(ev.ShadowChanges, fmt.Sprintf("service %s running unregistered digest %s", ra.Service, ra.SHA256))
					} else {
						// Check if registered artifact has drift (failing controls)
						var trailID sql.NullString
						s.q(r.Context()).QueryRowContext(r.Context(), "SELECT trail_id FROM artifacts WHERE sha256 = $1 LIMIT 1", ra.SHA256).Scan(&trailID)
						if trailID.Valid {
							var compliantCount, totalCount int
							s.q(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*), SUM(CASE WHEN is_compliant THEN 1 ELSE 0 END) FROM attestations WHERE trail_id = $1", trailID.String).Scan(&totalCount, &compliantCount)
							if totalCount > 0 && compliantCount < totalCount {
								ev.Drifts = append(ev.Drifts, fmt.Sprintf("service %s running drifted artifact %s (failing controls)", ra.Service, ra.SHA256))
							}
						}
					}
				}
			}
		}
	}

	// Fetch MCP servers configured for this environment
	type MCPServerView struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Transport  string   `json:"transport"`
		Command    string   `json:"command"`
		Args       []string `json:"args"`
		URL        string   `json:"url"`
		AuthHeader string   `json:"auth_header"`
	}
	var mcpServers []MCPServerView
	queryMcp := `SELECT id, name, transport, COALESCE(command, ''), args, COALESCE(url, ''), COALESCE(auth_header, '') 
	             FROM environment_mcp_servers WHERE environment_id = $1`
	mcpRows, err := s.q(r.Context()).QueryContext(r.Context(), queryMcp, envID)
	if err == nil {
		defer mcpRows.Close()
		for mcpRows.Next() {
			var m MCPServerView
			var args pq.StringArray
			if err := mcpRows.Scan(&m.ID, &m.Name, &m.Transport, &m.Command, &args, &m.URL, &m.AuthHeader); err == nil {
				m.Args = []string(args)
				mcpServers = append(mcpServers, m)
			}
		}
	}

	// Build the report struct
	report := struct {
		Environment EnvironmentView `json:"environment"`
		MCPServers  []MCPServerView `json:"mcp_servers"`
		ExportedAt  string          `json:"exported_at"`
	}{
		Environment: ev,
		MCPServers:  mcpServers,
		ExportedAt:  time.Now().Format(time.RFC3339),
	}

	fileName := fmt.Sprintf("audit-report-%s.json", name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	json.NewEncoder(w).Encode(report)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := `SELECT id, name, COALESCE(description, '') AS description, rules FROM policies WHERE org_id = $1`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, orgID)
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

	var list []*PolicyView
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
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

func (s *Server) handleListAIAssessments(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Scope to the caller's tenant via attestation -> trail -> flow -> org.
	query := `SELECT la.id, att.name, la.model_provider, la.model_name, la.assessment_raw, la.compliance_score, la.created_at
	          FROM llm_assessments la
	          JOIN attestations att ON la.attestation_id = att.id
	          JOIN trails tr ON att.trail_id = tr.id
	          JOIN flows f ON tr.flow_id = f.id
	          WHERE f.org_id = $1
	          ORDER BY la.created_at DESC`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type AssessmentView struct {
		ID              string    `json:"id"`
		AttestationName string    `json:"attestationName"`
		ModelProvider   string    `json:"modelProvider"`
		ModelName       string    `json:"modelName"`
		AssessmentRaw   string    `json:"assessmentRaw"`
		ComplianceScore int       `json:"complianceScore"`
		CreatedAt       time.Time `json:"createdAt"`
	}

	var list []*AssessmentView
	for rows.Next() {
		var av AssessmentView
		if err := rows.Scan(&av.ID, &av.AttestationName, &av.ModelProvider, &av.ModelName, &av.AssessmentRaw, &av.ComplianceScore, &av.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &av)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

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

type saveTenantSettingsReq struct {
	OrgID   string                        `json:"org_id"`
	Auth    *models.TenantAuthConfig      `json:"auth"`
	Storage *models.TenantStorageSettings `json:"storage"`
	Vault   *models.TenantVaultSettings   `json:"vault"`
	LLM     *models.TenantLLMSettings     `json:"llm"`
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

type generatePolicyReq struct {
	Framework   string `json:"framework"`
	Description string `json:"description"`
}

func (s *Server) handleAIGeneratePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req generatePolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	var rawResponse string
	var err error

	if s.LLM != nil {
		rawResponse, err = s.LLM.GeneratePolicy(r.Context(), req.Framework, req.Description)
	} else {
		rawResponse = fmt.Sprintf(`{
  "name": "%s-compliance-policy",
  "description": "LLM Generated Policy for %s compliance: %s",
  "rules": {
    "controls": [
      {
        "name": "vulnerability-check",
        "attestation_type": "snyk-scan",
        "jq_expressions": [
          ".vulnerabilities.critical == 0"
        ]
      },
      {
        "name": "unit-test-verification",
        "attestation_type": "junit",
        "jq_expressions": [
          ".failures == 0",
          ".errors == 0"
        ]
      }
    ]
  }
}`, req.Framework, req.Framework, req.Description)
	}

	if err != nil {
		rawResponse = fmt.Sprintf(`{
  "name": "%s-compliance-policy",
  "description": "LLM Fallback Policy for %s compliance: %s",
  "rules": {
    "controls": [
      {
        "name": "vulnerability-check",
        "attestation_type": "snyk-scan",
        "jq_expressions": [
          ".vulnerabilities.critical == 0"
        ]
      }
    ]
  }
}`, req.Framework, req.Framework, req.Description)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(rawResponse))
}

type aiChatReq struct {
	Message string           `json:"message"`
	History []ai.ChatMessage `json:"history"`
}

type aiChatResp struct {
	Response string `json:"response"`
}

func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req aiChatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	ctx := r.Context()
	userMsg := req.Message
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var answer string
	var executionOutput string

	var flowName, flowDesc string
	if n, _ := fmt.Sscanf(userMsg, "create flow %s description %s", &flowName, &flowDesc); n >= 1 {
		flowID := uuid.New()
		query := `INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at) VALUES ($1, $2, $3, $4, '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		_, err := s.q(ctx).ExecContext(ctx, query, flowID, orgID, flowName, flowDesc)
		if err != nil {
			executionOutput = fmt.Sprintf("\n*(Failed to create flow: %v)*", err)
		} else {
			executionOutput = fmt.Sprintf("\n*(Flow '%s' successfully created with ID: %s)*", flowName, flowID)
		}
	} else if n, _ := fmt.Sscanf(userMsg, "create flow %s", &flowName); n == 1 {
		flowID := uuid.New()
		query := `INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at) VALUES ($1, $2, $3, 'Created via LLM Assistant', '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		_, err := s.q(ctx).ExecContext(ctx, query, flowID, orgID, flowName)
		if err != nil {
			executionOutput = fmt.Sprintf("\n*(Failed to create flow: %v)*", err)
		} else {
			executionOutput = fmt.Sprintf("\n*(Flow '%s' successfully created with ID: %s)*", flowName, flowID)
		}
	}

	if s.LLM != nil {
		var err error
		answer, err = s.LLM.Chat(ctx, req.History, userMsg)
		if err != nil {
			answer = "I processed your request, but I encountered an error communicating with the local LLM. " + err.Error()
		}
	} else {
		if flowName != "" {
			answer = fmt.Sprintf("I've successfully created a new compliance pipeline flow named **%s** for tracking your software components.", flowName)
		} else if userMsg == "list flows" || userMsg == "show flows" {
			rows, _ := s.q(ctx).QueryContext(ctx, "SELECT name, COALESCE(description, '') FROM flows")
			defer rows.Close()
			answer = "Here are the currently configured compliance flows in Fides:\n\n"
			for rows.Next() {
				var name, desc string
				rows.Scan(&name, &desc)
				answer += fmt.Sprintf("- **%s**: %s\n", name, desc)
			}
		} else if userMsg == "find failing trails" || userMsg == "failing builds" {
			query := `SELECT t.name, f.name, att.name, att.type_name
			          FROM attestations att
			          JOIN trails t ON att.trail_id = t.id
			          JOIN flows f ON t.flow_id = f.id
			          WHERE att.is_compliant = false`
			rows, _ := s.q(ctx).QueryContext(ctx, query)
			defer rows.Close()
			answer = "### Non-Compliant Trails Alert\nI scanned the trails database and found the following non-compliant build items:\n\n"
			found := false
			for rows.Next() {
				var tName, fName, attName, typeName string
				rows.Scan(&tName, &fName, &attName, &typeName)
				answer += fmt.Sprintf("- **Flow `%s` / Build `%s`**: Failed control `%s` (Type: `%s`)\n", fName, tName, attName, typeName)
				found = true
			}
			if !found {
				answer = "Great news! All recorded build trails are fully compliant against current policies."
			}
		} else {
			answer = "Hello! I am **Fides**, your compliance & audit conversational assistant. I can help you configure flows and trails, search failing builds, audit artifacts, and verify SOC 2 or ISO 27001 readiness.\n\nTry asking me:\n- `create flow frontend-service` (Creates a pipeline flow)\n- `list flows` (Displays registered pipelines)\n- `find failing trails` (Audits failing CI/CD builds)"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aiChatResp{
		Response: answer + executionOutput,
	})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type setPasswordReq struct {
	Password string `json:"password"`
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
	var u models.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		badRequest(w, err)
		return
	}

	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u.OrgID = orgID

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

	var list []models.TenantWebhook
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

// handleAdmissionValidate is the Kubernetes ValidatingAdmissionWebhook entry
// point. It denies Pods whose image digests are unregistered (shadow) or
// non-compliant in Fides. Tenant from FIDES_ADMISSION_ORG_ID; mode from
// FIDES_ADMISSION_MODE ("enforce" denies, default "audit" warns only).
func (s *Server) handleAdmissionValidate(w http.ResponseWriter, r *http.Request) {
	var review admission.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		badRequest(w, err)
		return
	}

	uid := ""
	if review.Request != nil {
		uid = review.Request.UID
	}

	writeReview := func(resp *admission.AdmissionResponse) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(admission.AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Response:   resp,
		})
	}

	orgID, err := uuid.Parse(os.Getenv("FIDES_ADMISSION_ORG_ID"))
	if err != nil {
		// Misconfiguration must not break the cluster: allow with a warning.
		// (Use the webhook's failurePolicy for hard availability guarantees.)
		writeReview(&admission.AdmissionResponse{UID: uid, Allowed: true,
			Warnings: []string{"Fides admission: FIDES_ADMISSION_ORG_ID not configured; allowing"}})
		return
	}

	mode := admission.Mode(os.Getenv("FIDES_ADMISSION_MODE"))
	if mode != admission.ModeEnforce {
		mode = admission.ModeAudit // safe default
	}

	rv := &admission.Reviewer{Checker: admission.NewDBChecker(s.DB), Mode: mode}
	writeReview(rv.Review(r.Context(), orgID, review.Request))
}

// handleInboundWebhook ingests a signed GitHub/GitLab push webhook and auto-
// creates a flow + trail for the commit. Authenticated by the provider's
// HMAC/token signature against the tenant's configured inbound secret.
func (s *Server) handleInboundWebhook(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider != inbound.GitHub && provider != inbound.GitLab {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	orgID, err := uuid.Parse(r.URL.Query().Get("org"))
	if err != nil {
		http.Error(w, "valid org query param is required", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		badRequest(w, err)
		return
	}

	// Resolve the tenant's inbound secret for this provider.
	var secretPath string
	_ = db.WithOrgScope(r.Context(), s.DB, orgID.String(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(r.Context(),
			`SELECT COALESCE(inbound_secret_path, '') FROM tenant_git_providers
			 WHERE org_id = $1 AND provider = $2 AND enabled AND inbound_secret_path IS NOT NULL LIMIT 1`,
			orgID, provider).Scan(&secretPath)
	})
	if secretPath == "" {
		http.Error(w, "inbound webhooks not configured for this provider", http.StatusBadRequest)
		return
	}
	secret, err := s.Secrets.GetSecret(r.Context(), "", secretPath)
	if err != nil {
		internalError(w, err)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if provider == inbound.GitLab {
		sig = r.Header.Get("X-Gitlab-Token")
	}
	if !inbound.Verify(provider, secret, sig, body) {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}

	ti, ok := inbound.ParsePush(provider, body)
	if !ok {
		// Not a push (or unparseable) — acknowledge without creating a trail.
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"ignored"}`))
		return
	}

	// Find/create the flow (by repo full name) and create the trail, org-scoped.
	trailID := uuid.New()
	err = db.WithOrgScope(r.Context(), s.DB, orgID.String(), func(tx *sql.Tx) error {
		var flowID uuid.UUID
		e := tx.QueryRowContext(r.Context(), `SELECT id FROM flows WHERE org_id = $1 AND name = $2`, orgID, ti.FullName).Scan(&flowID)
		if e == sql.ErrNoRows {
			flowID = uuid.New()
			if _, e = tx.ExecContext(r.Context(),
				`INSERT INTO flows (id, org_id, name, description) VALUES ($1, $2, $3, $4)`,
				flowID, orgID, ti.FullName, "Auto-created from "+provider+" webhook"); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		commit := ti.Commit
		name := commit
		if len(name) > 12 {
			name = name[:12]
		}
		_, e = tx.ExecContext(r.Context(),
			`INSERT INTO trails (id, flow_id, name, git_repository, git_commit, git_branch, git_message)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			trailID, flowID, name, ti.Repository, commit, ti.Branch, ti.Message)
		return e
	})
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "trail_created", "trail_id": trailID.String(),
		"repository": ti.FullName, "commit": ti.Commit, "branch": ti.Branch,
	})
}

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
		_ = events.Enqueue(r.Context(), s.DB, orgID, "compliance.evaluated", map[string]any{
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

	var list []models.TenantGitProvider
	for rows.Next() {
		var gp models.TenantGitProvider
		if err := rows.Scan(&gp.ID, &gp.OrgID, &gp.Provider, &gp.Host, &gp.APIBase, &gp.TokenPath, &gp.InboundSecretPath, &gp.Enabled, &gp.CreatedAt, &gp.UpdatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, gp)
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
	if (gp.Provider != "github" && gp.Provider != "gitlab") || gp.Host == "" || gp.APIBase == "" || gp.TokenPath == "" {
		http.Error(w, "provider (github|gitlab), host, api_base, and token_path are required", http.StatusBadRequest)
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

func (s *Server) handleListEnvironmentMCPServers(w http.ResponseWriter, r *http.Request) {
	envIDStr := r.URL.Query().Get("environment_id")
	if envIDStr == "" {
		http.Error(w, "missing environment_id query param", http.StatusBadRequest)
		return
	}
	envID, err := uuid.Parse(envIDStr)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}

	query := `SELECT id, environment_id, name, transport, COALESCE(command, ''), args, env_vars, COALESCE(url, ''), COALESCE(auth_header, ''), created_at, updated_at 
	          FROM environment_mcp_servers WHERE environment_id = $1`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	var list []models.EnvironmentMCPServer
	for rows.Next() {
		var srv models.EnvironmentMCPServer
		var args pq.StringArray
		var envVarsBytes []byte
		err := rows.Scan(
			&srv.ID, &srv.EnvironmentID, &srv.Name, &srv.Transport,
			&srv.Command, &args, &envVarsBytes, &srv.URL, &srv.AuthHeader,
			&srv.CreatedAt, &srv.UpdatedAt,
		)
		if err != nil {
			internalError(w, err)
			return
		}
		srv.Args = []string(args)
		json.Unmarshal(envVarsBytes, &srv.EnvVars)
		list = append(list, srv)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleSaveEnvironmentMCPServer(w http.ResponseWriter, r *http.Request) {
	var req models.EnvironmentMCPServer
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	if req.Name == "" || req.Transport == "" {
		http.Error(w, "name and transport are required", http.StatusBadRequest)
		return
	}

	envVarsJSON, err := json.Marshal(req.EnvVars)
	if err != nil {
		http.Error(w, "invalid env_vars", http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO environment_mcp_servers (environment_id, name, transport, command, args, env_vars, url, auth_header, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
		ON CONFLICT (environment_id, name) DO UPDATE SET
			transport = EXCLUDED.transport,
			command = EXCLUDED.command,
			args = EXCLUDED.args,
			env_vars = EXCLUDED.env_vars,
			url = EXCLUDED.url,
			auth_header = EXCLUDED.auth_header,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id, created_at, updated_at`

	err = s.q(r.Context()).QueryRowContext(r.Context(), query,
		req.EnvironmentID, req.Name, req.Transport, req.Command, pq.Array(req.Args), envVarsJSON, req.URL, req.AuthHeader,
	).Scan(&req.ID, &req.CreatedAt, &req.UpdatedAt)

	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

type queryMCPReq struct {
	EnvironmentID string                 `json:"environment_id"`
	ServerName    string                 `json:"server_name"`
	ToolName      string                 `json:"tool_name"`
	Arguments     map[string]interface{} `json:"arguments"`
}

func (s *Server) handleQueryEnvironmentMCPServer(w http.ResponseWriter, r *http.Request) {
	var req queryMCPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}

	// Fetch MCP server configuration
	var srv models.EnvironmentMCPServer
	var args pq.StringArray
	var envVarsBytes []byte
	query := `SELECT id, environment_id, name, transport, COALESCE(command, ''), args, env_vars, COALESCE(url, ''), COALESCE(auth_header, '')
	          FROM environment_mcp_servers WHERE environment_id = $1 AND name = $2 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), query, envID, req.ServerName).Scan(
		&srv.ID, &srv.EnvironmentID, &srv.Name, &srv.Transport,
		&srv.Command, &args, &envVarsBytes, &srv.URL, &srv.AuthHeader,
	)
	if err == sql.ErrNoRows {
		http.Error(w, "MCP server configuration not found for this environment", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	srv.Args = []string(args)
	json.Unmarshal(envVarsBytes, &srv.EnvVars)

	if srv.Transport != "stdio" {
		http.Error(w, "Only stdio transport is supported currently in this environment", http.StatusBadRequest)
		return
	}

	// Execute tool call on MCP server
	output, err := mcp.CallToolStdio(srv.Command, srv.Args, srv.EnvVars, req.ToolName, req.Arguments)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"result": %q}`, output)))
}

type verifyEnvReq struct {
	EnvironmentID string                 `json:"environment_id"`
	ServerName    string                 `json:"server_name"`
	ToolName      string                 `json:"tool_name"`
	Arguments     map[string]interface{} `json:"arguments"`
	Rules         []string               `json:"rules"`
}

func (s *Server) handleVerifyEnvironmentCompliance(w http.ResponseWriter, r *http.Request) {
	var req verifyEnvReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}

	// Fetch MCP server configuration
	var srv models.EnvironmentMCPServer
	var args pq.StringArray
	var envVarsBytes []byte
	query := `SELECT id, environment_id, name, transport, COALESCE(command, ''), args, env_vars, COALESCE(url, ''), COALESCE(auth_header, '')
	          FROM environment_mcp_servers WHERE environment_id = $1 AND name = $2 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), query, envID, req.ServerName).Scan(
		&srv.ID, &srv.EnvironmentID, &srv.Name, &srv.Transport,
		&srv.Command, &args, &envVarsBytes, &srv.URL, &srv.AuthHeader,
	)
	if err == sql.ErrNoRows {
		http.Error(w, "MCP server configuration not found for this environment", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	srv.Args = []string(args)
	json.Unmarshal(envVarsBytes, &srv.EnvVars)

	if srv.Transport != "stdio" {
		http.Error(w, "Only stdio transport is supported currently in this environment", http.StatusBadRequest)
		return
	}

	// Execute tool call on MCP server
	output, err := mcp.CallToolStdio(srv.Command, srv.Args, srv.EnvVars, req.ToolName, req.Arguments)
	if err != nil {
		internalError(w, err)
		return
	}

	// Evaluate rules deterministically using PolicyEngine
	compliant, failedRules, err := s.PolicyEngine.EvaluateAttestation(output, req.Rules)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"compliant":    compliant,
		"failed_rules": failedRules,
		"raw_response": output,
	})
}
