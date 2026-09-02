package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"fides/pkg/admission"
	"fides/pkg/ai"
	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/db"
	"fides/pkg/events"
	"fides/pkg/inbound"
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
	// Sessions are in-memory by default; opt into the persistent Postgres-backed
	// store (survives restarts, shared across replicas) with FIDES_DB_SESSIONS=true
	// once migration 0020 has been applied.
	sessions := auth.NewSessionStore()
	if os.Getenv("FIDES_DB_SESSIONS") == "true" {
		sessions = auth.NewDBSessionStore(db)
	}
	return &Server{
		DB:           db,
		Storage:      store,
		PolicyEngine: policy.NewPolicyEngine(),
		LLM:          llm,
		Secrets:      vault.NewProvider(context.Background()),
		States:       auth.NewStateStore(),
		Sessions:     sessions,
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
	mux.HandleFunc("GET /api/v1/flows/{id}/trails", s.handleListFlowTrails)
	mux.HandleFunc("GET /api/v1/flows/{id}/artifacts", s.handleListFlowArtifacts)
	// Canonical evidence deep link (name or UUID) -> portal redirect. Must stay
	// under /api/v1/: isPublicPath treats everything else as public, and an
	// unauthenticated resolver would be a trail-enumeration surface.
	mux.HandleFunc("GET /api/v1/evidence/flows/{flow}/trails/{trail}", s.handleEvidenceLink)

	// Trail API
	mux.HandleFunc("POST /api/v1/trails", s.handleCreateTrail)
	mux.HandleFunc("GET /api/v1/trails/{id}/verify-chain", s.handleVerifyTrailChain)
	// Anchor a trail's chain head to an external RFC3161 timestamp authority (#297).
	mux.HandleFunc("POST /api/v1/trails/{id}/anchor", s.handleCreateTrailAnchor)
	mux.HandleFunc("GET /api/v1/trails/{id}/change-gate", s.handleChangeGate)
	mux.HandleFunc("GET /api/v1/trails/{id}/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /api/v1/trails/{id}/approvals", s.handleRecordApproval)
	mux.HandleFunc("GET /api/v1/trails/{id}/audit-package", s.handleTrailAuditPackage)
	mux.HandleFunc("GET /api/v1/trails/{id}/deployment-anchors", s.handleListDeploymentAnchors)

	// Search / query + snapshot diff
	mux.HandleFunc("GET /api/v1/search/artifacts", s.handleSearchArtifacts)
	mux.HandleFunc("GET /api/v1/search/attestations", s.handleSearchAttestations)
	mux.HandleFunc("GET /api/v1/search/components", s.handleSearchComponents)
	// CVE -> artifact -> environment impact index + VEX suppression (issue #294).
	mux.HandleFunc("GET /api/v1/impact", s.handleImpact)
	mux.HandleFunc("POST /api/v1/vex", s.handleRecordVEX)
	// Backfill the CVE index from pre-existing scan attestations (#315).
	mux.HandleFunc("POST /api/v1/vulnerabilities/backfill", s.handleBackfillVulnerabilities)
	mux.HandleFunc("GET /api/v1/attestations/{id}", s.handleGetAttestation)
	mux.HandleFunc("GET /api/v1/environments/{id}/snapshots/diff", s.handleSnapshotDiff)

	// Post-approval drift re-evaluation: diff an environment's snapshots and,
	// if drift is detected, write an elevated risk note back onto the
	// ServiceNow change request that approved the prior state (ServiceNow has
	// no native post-approval re-scoring).
	mux.HandleFunc("POST /api/v1/environments/{id}/snapshots/reevaluate-change", s.handleDriftReevaluateChange)

	// DORA-style delivery metrics
	mux.HandleFunc("GET /api/v1/metrics/dora", s.handleDoraMetrics)
	mux.HandleFunc("GET /api/v1/metrics/deployment-frequency", s.handleDeploymentFrequency)
	mux.HandleFunc("GET /api/v1/metrics/compliance-correlation", s.handleComplianceCorrelation)

	// Governance controls + coverage
	mux.HandleFunc("GET /api/v1/controls", s.handleListControls)
	mux.HandleFunc("POST /api/v1/controls", s.handleCreateControl)
	mux.HandleFunc("GET /api/v1/controls/coverage", s.handleControlsCoverage)
	mux.HandleFunc("GET /api/v1/controls/timeline", s.handleControlTimeline)
	mux.HandleFunc("POST /api/v1/controls/{id}/archive", s.handleArchiveControl)
	mux.HandleFunc("POST /api/v1/controls/{id}/unarchive", s.handleUnarchiveControl)
	mux.HandleFunc("POST /api/v1/controls/{key}/enforce", s.handleEnforceControl)
	mux.HandleFunc("GET /api/v1/frameworks", s.handleListFrameworks)
	mux.HandleFunc("GET /api/v1/control-catalog", s.handleControlCatalog)
	mux.HandleFunc("GET /api/v1/risk-register", s.handleRiskRegister)
	mux.HandleFunc("GET /api/v1/exceptions", s.handleListExceptions)
	mux.HandleFunc("POST /api/v1/exceptions", s.handleCreateException)
	mux.HandleFunc("POST /api/v1/exceptions/{id}/revoke", s.handleRevokeException)
	mux.HandleFunc("GET /api/v1/sdlc", s.handleSDLC)
	mux.HandleFunc("GET /api/v1/audit-pack", s.handleAuditPack)
	mux.HandleFunc("GET /api/v1/services", s.handleListServices)
	mux.HandleFunc("POST /api/v1/services", s.handleSaveService)
	mux.HandleFunc("GET /api/v1/training", s.handleListTraining)
	mux.HandleFunc("POST /api/v1/training", s.handleRecordTraining)
	mux.HandleFunc("POST /api/v1/verify-branch-protection", s.handleVerifyBranchProtection)
	mux.HandleFunc("POST /api/v1/controls/import-framework", s.handleImportFramework)
	mux.HandleFunc("GET /api/v1/reports/framework/{framework}", s.handleFrameworkReport)
	// EU CRA 24h exploited-vulnerability / incident reporting set (#293).
	mux.HandleFunc("GET /api/v1/reports/cra-incidents", s.handleCRAIncidents)

	// Slack notification settings
	mux.HandleFunc("GET /api/v1/tenant/slack", s.handleGetSlack)
	mux.HandleFunc("POST /api/v1/tenant/slack", s.handleSaveSlack)

	// Logical environments (aggregate physical environments)
	mux.HandleFunc("GET /api/v1/logical-environments", s.handleListLogicalEnv)
	mux.HandleFunc("POST /api/v1/logical-environments", s.handleCreateLogicalEnv)
	mux.HandleFunc("POST /api/v1/logical-environments/{id}/members", s.handleAddLogicalMember)
	mux.HandleFunc("DELETE /api/v1/logical-environments/{id}/members/{envId}", s.handleRemoveLogicalMember)
	mux.HandleFunc("GET /api/v1/logical-environments/{id}/state", s.handleLogicalEnvState)

	// Environment policies (required attestation types, tag-conditional) + tags
	mux.HandleFunc("GET /api/v1/environments/{id}/policies", s.handleListEnvPolicies)
	mux.HandleFunc("POST /api/v1/environments/{id}/policies", s.handleCreatePolicy)
	mux.HandleFunc("DELETE /api/v1/environments/{id}/policies/{policyId}", s.handleDeletePolicy)
	mux.HandleFunc("GET /api/v1/environments/{id}/policy-check", s.handlePolicyCheck)
	mux.HandleFunc("POST /api/v1/environments/{id}/tags", s.handleSetEnvTags)
	mux.HandleFunc("POST /api/v1/flows/{id}/tags", s.handleSetFlowTags)

	// Per-environment artifact allow-list (explicit approvals)
	mux.HandleFunc("GET /api/v1/environments/{id}/allowlist", s.handleListAllowlist)
	mux.HandleFunc("POST /api/v1/environments/{id}/allowlist", s.handleAddAllowlist)
	mux.HandleFunc("DELETE /api/v1/environments/{id}/allowlist/{sha}", s.handleRemoveAllowlist)

	// Policy-driven auto-remediation (proposed -> approved|rejected -> applied),
	// gated by an approval record before an action can be applied (issue #235).
	mux.HandleFunc("POST /api/v1/remediation", s.handleProposeRemediation)
	mux.HandleFunc("GET /api/v1/remediation", s.handleListRemediation)
	mux.HandleFunc("GET /api/v1/remediation/{id}", s.handleGetRemediation)
	mux.HandleFunc("POST /api/v1/remediation/{id}/approve", s.handleApproveRemediation)
	mux.HandleFunc("POST /api/v1/remediation/{id}/reject", s.handleRejectRemediation)
	mux.HandleFunc("POST /api/v1/remediation/{id}/apply", s.handleApplyRemediation)

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
	mux.HandleFunc("POST /api/v1/environments", s.handleCreateEnvironment)
	mux.HandleFunc("POST /api/v1/environments/{id}/archive", s.handleArchiveEnvironment)
	mux.HandleFunc("POST /api/v1/environments/{id}/unarchive", s.handleUnarchiveEnvironment)
	mux.HandleFunc("GET /api/v1/environments/export", s.handleExportEnvironmentAudit)
	mux.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	mux.HandleFunc("POST /api/v1/policies", s.handleSavePolicy)
	mux.HandleFunc("POST /api/v1/policies/create", s.handleCreatePolicyGlobal)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", s.handleDeletePolicyGlobal)
	mux.HandleFunc("GET /api/v1/ai-assessments", s.handleListAIAssessments)

	// Tenant Webhooks (signed outbound delivery)
	mux.HandleFunc("GET /api/v1/tenant/webhooks", s.handleListWebhooks)
	mux.HandleFunc("POST /api/v1/tenant/webhooks", s.handleSaveWebhook)

	// Tenant Git Providers (CI/CD commit-status gating)
	mux.HandleFunc("GET /api/v1/tenant/git-providers", s.handleListGitProviders)
	mux.HandleFunc("POST /api/v1/tenant/git-providers", s.handleSaveGitProvider)

	// Ingest platform-native attestations (GitHub Artifact Attestations,
	// GitLab Attestations) for a built artifact, using the tenant's configured
	// git-provider token, and record them onto the matching trail/artifact.
	mux.HandleFunc("POST /api/v1/attest/fetch", s.handleAttestFetch)

	// Tenant ServiceNow settings (CMDB/ITOM/ITSM)
	mux.HandleFunc("GET /api/v1/tenant/servicenow", s.handleGetServiceNow)
	mux.HandleFunc("POST /api/v1/tenant/servicenow", s.handleSaveServiceNow)
	mux.HandleFunc("GET /api/v1/tenant/servicenow/events", s.handleServiceNowEvents)

	// Assurance console summary — powers the source-owned portal frontpage
	// (portal/src/app/(portal)/page.tsx). The Go-served HTML pages that used to
	// live here (/console, /admin, /servicenow, /evidence) were removed after the
	// portal cutover; only their backing APIs remain.
	mux.HandleFunc("GET /api/v1/console/summary", s.handleConsoleSummary)
	mux.HandleFunc("GET /api/v1/console/stream", s.handleConsoleStream)

	// ITSM change-control gate: fetch a ServiceNow change request and record a
	// servicenow-change attestation evaluated against its jq rules.
	mux.HandleFunc("POST /api/v1/servicenow/change-check", s.handleServiceNowChangeCheck)
	mux.HandleFunc("POST /api/v1/servicenow/change-gate", s.handleServiceNowChangeGate)

	// Change<->Control linkage (#227): record that a ServiceNow change implemented
	// a Fides control via a specific attestation, and reference it back on the
	// change_request.
	mux.HandleFunc("POST /api/v1/servicenow/link-control", s.handleServiceNowLinkControl)

	// Inbound CI/CD webhooks: auto-create a trail from a signed push event.
	// Public: authenticated by the provider's HMAC/token signature, not a bearer.
	mux.HandleFunc("POST /api/v1/webhooks/{provider}", s.handleInboundWebhook)
	// Feature-flag change governance: record a flag change as a flag.changed
	// attestation on a trail (epic #286 / #287).
	mux.HandleFunc("POST /api/v1/flags/changed", s.handleRecordFlagChange)
	// Provider webhook adapters (Unleash/Flagsmith) -> flag.changed (#290).
	mux.HandleFunc("POST /api/v1/flags/webhook/{provider}", s.handleFlagWebhook)
	// Flag-change history for auditors + the /admin console (#291).
	mux.HandleFunc("GET /api/v1/flags/history", s.handleFlagHistory)

	// ServiceNow read/action endpoints (backing the MCP tools)
	mux.HandleFunc("GET /api/v1/servicenow/change-status", s.handleServiceNowChangeStatus)
	mux.HandleFunc("POST /api/v1/servicenow/incident", s.handleServiceNowCreateIncident)
	mux.HandleFunc("GET /api/v1/servicenow/cmdb", s.handleServiceNowSearchCMDB)

	// Deployment provenance anchoring: on change close / deploy, attach the
	// signed deployment attestation (image digest, commit, build log ref,
	// runtime snapshot ref) to the relevant CMDB CI.
	mux.HandleFunc("POST /api/v1/servicenow/deployment-anchor", s.handleServiceNowAnchorDeployment)

	// Now Assist grounding: authoritative control-coverage + evidence for a change.
	mux.HandleFunc("GET /api/v1/servicenow/grounding", s.handleServiceNowGrounding)

	// Fides as a remote MCP server (Streamable HTTP) for Now Assist / AI clients.
	mux.HandleFunc("POST /api/v1/mcp", s.handleMCPServer)

	// ServiceNow MCP client: consume ServiceNow's Model Context Protocol server
	// (discover servers, governed record lookup, list/call tools).
	mux.HandleFunc("GET /api/v1/servicenow/mcp/servers", s.handleSNMCPServers)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/lookup", s.handleSNMCPLookup)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/tools", s.handleSNMCPTools)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/call", s.handleSNMCPCall)

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
	mux.HandleFunc("GET /api/v1/tenant/service-accounts/{id}/keys", s.handleListServiceAccountKeys)
	mux.HandleFunc("POST /api/v1/tenant/service-accounts/{id}/keys", s.handleIssueServiceAccountKey)
	mux.HandleFunc("DELETE /api/v1/tenant/service-accounts/{id}/keys/{keyId}", s.handleRevokeServiceAccountKey)
	mux.HandleFunc("POST /api/v1/tenant/service-accounts/{id}/delegation", s.handleSetServiceAccountDelegation)
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
	mux.HandleFunc("POST /api/v1/ai/lint-policy", s.handleAILintPolicy)
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
	// Rescue for the evidence URLs already written into ServiceNow as immutable
	// audit records (see evidence_link.go). More specific than "GET /", so it
	// wins under ServeMux precedence while /flows/ (the portal page) stays with
	// the FileServer.
	mux.HandleFunc("GET /flows/{flow}/trails/{trail}", handleLegacyEvidenceLink)
	mux.Handle("GET /", fs)

	return securityHeaders(limitBody(s.authMiddleware(telemetry.Middleware(mux))))
}

// maxRequestBody caps request body size to mitigate memory-exhaustion DoS.
// It is generous enough to accommodate multipart evidence uploads.
const maxRequestBody = 64 << 20 // 64 MiB

const sessionCookieName = "fides_session"

// q returns the tenant-scoped Querier for this request when RLS scoping is
// active, otherwise the unscoped connection pool. This makes handler queries
// behavior-identical when RLS is disabled.
func (s *Server) q(ctx context.Context) db.Querier {
	if scoped, ok := db.QuerierFromContext(ctx); ok {
		return scoped
	}
	return s.DB
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
		// Best-effort by contract: the caller gets an empty map for anything
		// unparseable, which is what every call site already handles.
		//nolint:errcheck // documented above
		json.Unmarshal(data, &m)
	}
	return m
}

// REST Handlers

type createOrgReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleCreateOrg creates an organization.
//
// Admin-only. It used to be open to any authenticated principal, so a Viewer
// with a read-only token could mint tenants — and under RLS the WITH CHECK on
// organizations refuses it anyway, meaning the endpoint's behaviour depended on
// whether FIDES_RLS_ENABLED happened to be set.
//
// Admin is the improvement, not the destination: an Admin of one organization
// creating a second one is still odd, and a hosted deployment wants a separate
// bootstrap credential rather than a tenant role. That is a product decision;
// this is the fix that does not need one.
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.Role != auth.RoleAdmin {
		http.Error(w, "only Admins can create organizations", http.StatusForbidden)
		return
	}
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

// handleListOrgs lists the caller's organization.
//
// Scoped in the query, not left to the database. It previously selected every
// row, which returned every tenant's name and id to any authenticated
// principal — a Viewer in one organization could enumerate the customer list.
// Under RLS the policy on organizations hid that, but RLS is opt-in
// (FIDES_RLS_ENABLED), so with it unset the endpoint leaked, and the middleware
// contract above — the Principal's OrgID is the ONLY source of tenant scoping —
// was not being honoured here at all.
func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := `SELECT id, name, COALESCE(description, '') AS description, created_at
	          FROM organizations WHERE id = $1 ORDER BY name`
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []*models.Organization{}
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Description, &o.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &o)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
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

// handleUpdateFlow renames or retags a flow the caller owns.
//
// The org filter is the security control, not a tidiness: a flow id is not a
// secret — the API returns it and it appears in URLs — so without it any
// authenticated tenant could rename another tenant's pipeline by id alone.
// handleListFlows below has always scoped correctly; this was the inconsistency.
func (s *Server) handleUpdateFlow(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
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

	query := `UPDATE flows SET name = $1, description = $2, tags = $3, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $4 AND org_id = $5`
	res, err := s.q(r.Context()).ExecContext(r.Context(), query, req.Name, req.Description, marshalJSONB(req.Tags), flowID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	// Reported as not found rather than forbidden, so the response cannot be
	// used to test whether a given flow id exists in some other organization.
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		http.Error(w, "flow not found", http.StatusNotFound)
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

	list := []*models.Flow{}
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
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type createTrailReq struct {
	FlowID         string            `json:"flow_id"`
	Name           string            `json:"name"`
	GitRepository  string            `json:"git_repository"`
	GitCommit      string            `json:"git_commit"`
	GitBranch      string            `json:"git_branch"`
	GitMessage     string            `json:"git_message"`
	GitCommittedAt string            `json:"git_committed_at"` // RFC3339 commit timestamp (optional)
	Tags           map[string]string `json:"tags"`
}

// trailFieldHint turns Go's terse unknown-field error into one that names the
// field the caller almost certainly meant.
//
// The mistakes are not hypothetical: a CI pipeline sent commit/repository/branch
// for months and this endpoint answered 201 to every one of them, silently
// dropping all three, because encoding/json ignores fields it does not know.
// 316 trails were created with no git metadata and nothing anywhere said so.
func trailFieldHint(err error) error {
	msg := err.Error()
	for wrong, right := range map[string]string{
		"commit":       "git_commit",
		"repository":   "git_repository",
		"branch":       "git_branch",
		"message":      "git_message",
		"committed_at": "git_committed_at",
		"repo":         "git_repository",
		"sha":          "git_commit",
	} {
		if strings.Contains(msg, `unknown field "`+wrong+`"`) {
			return fmt.Errorf("%w — did you mean %q? The git fields are prefixed: "+
				"git_repository, git_commit, git_branch, git_message, git_committed_at", err, right)
		}
	}
	return err
}

func (s *Server) handleCreateTrail(w http.ResponseWriter, r *http.Request) {
	var req createTrailReq
	// Reject unknown fields rather than ignore them. A trail whose git metadata
	// was silently dropped looks identical to one that never had any, and the
	// consequences are invisible: the commit-status sink needs the repo and sha,
	// so it does not fail for such a trail — it never attempts anything at all.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Answer with the detail rather than the usual generic "invalid request".
		// badRequest hides internals on purpose, which is right in general — but
		// here the detail IS the caller's own field name, nothing internal, and
		// an unactionable 400 would repeat the original failure in a new form.
		log.Printf("bad request: create trail: %v", err)
		http.Error(w, trailFieldHint(err).Error(), http.StatusBadRequest)
		return
	}

	flowID, err := uuid.Parse(req.FlowID)
	if err != nil {
		http.Error(w, "invalid flow_id", http.StatusBadRequest)
		return
	}
	if !s.requireFlowInOrg(w, r, flowID) {
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

	// Optional git commit timestamp (RFC3339) for true code-to-prod lead time;
	// stored NULL if absent or unparseable (the metric falls back to created_at).
	var committedAt *time.Time
	if req.GitCommittedAt != "" {
		if t, perr := time.Parse(time.RFC3339, req.GitCommittedAt); perr == nil {
			committedAt = &t
		}
	}

	query := `INSERT INTO trails (id, flow_id, name, git_repository, git_commit, git_branch, git_message, git_committed_at, tags, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, trail.ID, trail.FlowID, trail.Name, trail.GitRepository, trail.GitCommit, trail.GitBranch, trail.GitMessage, committedAt, marshalJSONB(trail.Tags), trail.CreatedAt)
	if err != nil {
		// A duplicate trail name for the flow (UNIQUE(flow_id, name)) is a
		// client error, not a server fault — return 409 rather than 500.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			http.Error(w, "a trail with this name already exists for the flow", http.StatusConflict)
			return
		}
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

	// Keep a queryable CMDB image CI per digest so the change gate can anchor a
	// change's cmdb_ci to the binary it deployed (best-effort; the CMDB sink is
	// a no-op when ServiceNow is not configured for the org).
	_ = events.Enqueue(r.Context(), s.q(r.Context()), orgID, servicenow.ArtifactEventType, map[string]any{
		"sha256": req.SHA256, "name": req.Name, "type": req.Type,
	})

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

	list := []*ArtifactView{}
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
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// handleCheckCompliance answers whether an artifact passed its controls.
//
// Scoped to the caller's organization because the answer names the artifact and
// reports its compliance posture, and an image digest is not a secret — it is in
// every manifest and registry listing. Unscoped, anyone with an account could
// ask whether another organization's build passed, for any digest they knew.
func (s *Server) handleCheckCompliance(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sha := r.URL.Query().Get("sha256")
	if sha == "" {
		http.Error(w, "missing sha256 query param", http.StatusBadRequest)
		return
	}

	var name string
	var trailID sql.NullString
	// The attestation query below is keyed on this trail id, so scoping the
	// artifact scopes the whole answer: a trail reached from an artifact in the
	// caller's org is in the caller's org.
	queryArt := `SELECT name, trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1`
	err := s.q(r.Context()).QueryRowContext(r.Context(), queryArt, sha, orgID).Scan(&name, &trailID)
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
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
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

	list := []*AssessmentView{}
	for rows.Next() {
		var av AssessmentView
		if err := rows.Scan(&av.ID, &av.AttestationName, &av.ModelProvider, &av.ModelName, &av.AssessmentRaw, &av.ComplianceScore, &av.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &av)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type saveTenantSettingsReq struct {
	OrgID   string                        `json:"org_id"`
	Auth    *models.TenantAuthConfig      `json:"auth"`
	Storage *models.TenantStorageSettings `json:"storage"`
	Vault   *models.TenantVaultSettings   `json:"vault"`
	LLM     *models.TenantLLMSettings     `json:"llm"`
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

// handleAILintPolicy reviews a policy's jq-rules JSON for syntax errors and best
// practices and returns a corrected version. With an LLM configured it asks the
// model to fix and explain; without one it falls back to a deterministic JSON
// validity check + pretty-print so the button is always useful.
func (s *Server) handleAILintPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Rules string `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Rules) == "" {
		http.Error(w, "rules are required", http.StatusBadRequest)
		return
	}

	// Deterministic baseline used both as the no-LLM fallback and to detect change.
	var parsed any
	validJSON := json.Unmarshal([]byte(req.Rules), &parsed) == nil

	if s.LLM == nil {
		if !validJSON {
			writeJSON(w, map[string]any{"fixed": req.Rules, "changed": false,
				"notes": "Invalid JSON, and the AI reviewer is not configured. Fix the syntax (matching braces/brackets, quoted keys) and try again."})
			return
		}
		pretty, _ := json.MarshalIndent(parsed, "", "  ")
		writeJSON(w, map[string]any{"fixed": string(pretty), "changed": string(pretty) != req.Rules,
			"notes": "AI reviewer not configured — validated and formatted the JSON. No best-practice rewrite performed."})
		return
	}

	prompt := "You are reviewing a Fides compliance policy expressed as JSON containing jq rules. " +
		"The expected shape is {\"controls\":[{\"name\":\"...\",\"attestation_type\":\"...\",\"jq_expressions\":[\"...\"]}]} " +
		"(a bare {\"jq\":[...]} form is also valid). Check for JSON syntax errors and jq best practices: " +
		"valid structure, well-formed jq expressions, no duplicate/redundant rules, sensible names. " +
		"Respond with ONLY a JSON object, no markdown fences: " +
		"{\"fixed\": \"<the corrected policy as a JSON string>\", \"notes\": \"<short summary of what you changed, or why it's already fine>\"}.\n\nPolicy:\n" + req.Rules

	resp, err := s.LLM.Chat(r.Context(), nil, prompt)
	if err != nil {
		internalError(w, err)
		return
	}
	// Strip accidental markdown fences, then try to parse the model's {fixed,notes}.
	clean := strings.TrimSpace(resp)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)
	var out struct {
		Fixed string `json:"fixed"`
		Notes string `json:"notes"`
	}
	if json.Unmarshal([]byte(clean), &out) == nil && strings.TrimSpace(out.Fixed) != "" {
		writeJSON(w, map[string]any{"fixed": out.Fixed, "notes": out.Notes, "changed": out.Fixed != req.Rules})
		return
	}
	// Model didn't return the expected envelope — surface its text as notes and
	// keep the user's input unchanged.
	writeJSON(w, map[string]any{"fixed": req.Rules, "changed": false, "notes": strings.TrimSpace(resp)})
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

	// Deterministic commands are answered directly (fast, no LLM). Only freeform
	// questions hit the LLM, and with a timeout so a slow/unreachable model
	// returns a friendly message instead of hanging until the gateway 504s.
	lower := strings.ToLower(strings.TrimSpace(userMsg))
	switch {
	case flowName != "":
		answer = fmt.Sprintf("I've created a new compliance pipeline flow named **%s** for tracking your software components.", flowName)
	case lower == "list flows" || lower == "show flows":
		rows, _ := s.q(ctx).QueryContext(ctx, "SELECT name, COALESCE(description, '') FROM flows WHERE org_id = $1", orgID)
		defer rows.Close()
		answer = "Here are the currently configured compliance flows in Fides:\n\n"
		for rows.Next() {
			var name, desc string
			if err := rows.Scan(&name, &desc); err != nil {
				continue
			}
			answer += fmt.Sprintf("- **%s**: %s\n", name, desc)
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
	case lower == "find failing trails" || lower == "failing builds":
		query := `SELECT t.name, f.name, att.name, att.type_name
		          FROM attestations att
		          JOIN trails t ON att.trail_id = t.id
		          JOIN flows f ON t.flow_id = f.id
		          WHERE att.is_compliant = false AND f.org_id = $1`
		rows, _ := s.q(ctx).QueryContext(ctx, query, orgID)
		defer rows.Close()
		answer = "### Non-Compliant Trails Alert\nI scanned the trails database and found the following non-compliant build items:\n\n"
		found := false
		for rows.Next() {
			var tName, fName, attName, typeName string
			if err := rows.Scan(&tName, &fName, &attName, &typeName); err != nil {
				continue
			}
			answer += fmt.Sprintf("- **Flow `%s` / Build `%s`**: Failed control `%s` (Type: `%s`)\n", fName, tName, attName, typeName)
			found = true
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
		if !found {
			answer = "Great news! All recorded build trails are fully compliant against current policies."
		}
	case s.LLM != nil:
		lctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		a, err := s.LLM.Chat(lctx, req.History, userMsg)
		if err != nil {
			answer = "The assistant model didn't respond in time, or the LLM isn't reachable. You can still use commands like `list flows` or `find failing trails`, or check **Settings → Infrastructure → LLM Configuration**.\n\n_" + err.Error() + "_"
		} else {
			answer = a
		}
	default:
		answer = "Hello! I am **Fides**, your compliance & audit conversational assistant. I can help you configure flows and trails, search failing builds, audit artifacts, and verify SOC 2 or ISO 27001 readiness.\n\nTry asking me:\n- `create flow frontend-service` (Creates a pipeline flow)\n- `list flows` (Displays registered pipelines)\n- `find failing trails` (Audits failing CI/CD builds)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aiChatResp{
		Response: answer + executionOutput,
	})
}

type setPasswordReq struct {
	Password string `json:"password"`
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
		if errors.Is(e, sql.ErrNoRows) {
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
