package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fides/pkg/admission"
	"fides/pkg/ai"
	"fides/pkg/auth"
	"fides/pkg/db"
	"fides/pkg/inbound"
	"fides/pkg/models"
	"fides/pkg/policy"
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
	craNow       func() time.Time
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
	mux.HandleFunc("POST /api/v1/flows", withMutationRole(auth.RoleAdmin, s.handleCreateFlow))
	mux.HandleFunc("PUT /api/v1/flows", withMutationRole(auth.RoleAdmin, s.handleUpdateFlow))
	mux.HandleFunc("GET /api/v1/flows", s.handleListFlows)
	mux.HandleFunc("GET /api/v1/flows/{id}/trails", s.handleListFlowTrails)
	mux.HandleFunc("GET /api/v1/flows/{id}/artifacts", s.handleListFlowArtifacts)
	// Canonical evidence deep link (name or UUID) -> portal redirect. Must stay
	// under /api/v1/: isPublicPath treats everything else as public, and an
	// unauthenticated resolver would be a trail-enumeration surface.
	mux.HandleFunc("GET /api/v1/evidence/flows/{flow}/trails/{trail}", s.handleEvidenceLink)

	// Trail API
	mux.HandleFunc("POST /api/v1/trails", withMutationRole(auth.RoleWriter, s.handleCreateTrail))
	mux.HandleFunc("GET /api/v1/trails/{id}/verify-chain", s.handleVerifyTrailChain)
	// Anchor a trail's chain head to an external RFC3161 timestamp authority (#297).
	mux.HandleFunc("POST /api/v1/trails/{id}/anchor", s.handleCreateTrailAnchor)
	mux.HandleFunc("GET /api/v1/trails/{id}/change-gate", s.handleChangeGate)
	mux.HandleFunc("GET /api/v1/trails/{id}/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /api/v1/trails/{id}/approvals", s.handleRecordApproval)
	mux.HandleFunc("GET /api/v1/trails/{id}/audit-package", s.handleTrailAuditPackage)
	mux.HandleFunc("GET /api/v1/trails/{id}/signed-audit-pack", s.handleSignedAuditPack)
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
	mux.HandleFunc("POST /api/v1/environments/{id}/snapshots/reevaluate-change", withMutationRole(auth.RoleWriter, s.handleDriftReevaluateChange))

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
	mux.HandleFunc("POST /api/v1/exceptions", withMutationRole(auth.RoleAdmin, s.handleCreateException))
	mux.HandleFunc("POST /api/v1/exceptions/{id}/revoke", withMutationRole(auth.RoleAdmin, s.handleRevokeException))
	mux.HandleFunc("GET /api/v1/sdlc", s.handleSDLC)
	mux.HandleFunc("GET /api/v1/audit-pack", s.handleAuditPack)
	mux.HandleFunc("GET /api/v1/services", s.handleListServices)
	mux.HandleFunc("POST /api/v1/services", withMutationRole(auth.RoleAdmin, s.handleSaveService))
	mux.HandleFunc("GET /api/v1/training", s.handleListTraining)
	mux.HandleFunc("POST /api/v1/training", withMutationRole(auth.RoleWriter, s.handleRecordTraining))
	mux.HandleFunc("POST /api/v1/verify-branch-protection", withMutationRole(auth.RoleWriter, s.handleVerifyBranchProtection))
	mux.HandleFunc("POST /api/v1/controls/import-framework", s.handleImportFramework)
	mux.HandleFunc("GET /api/v1/reports/framework/{framework}", s.handleFrameworkReport)
	// EU CRA 24h exploited-vulnerability / incident reporting set (#293).
	mux.HandleFunc("GET /api/v1/reports/cra-incidents", s.handleCRAIncidents)
	mux.HandleFunc("GET /api/v1/cra/cases", s.craRoute("", false, s.listCRACases))
	mux.HandleFunc("POST /api/v1/cra/cases", s.craRoute(auth.RoleWriter, false, createCRACase))
	mux.HandleFunc("GET /api/v1/cra/cases/{id}", s.craRoute("", true, getCRACase))
	mux.HandleFunc("PATCH /api/v1/cra/cases/{id}", s.craRoute(auth.RoleWriter, true, patchCRACase))
	mux.HandleFunc("POST /api/v1/cra/cases/{id}/exports", s.craRoute(auth.RoleWriter, true, exportCRACase))
	mux.HandleFunc("POST /api/v1/cra/cases/{id}/submissions", s.craRoute(auth.RoleWriter, true, s.submitCRACase))

	// Slack notification settings
	mux.HandleFunc("GET /api/v1/tenant/slack", s.handleGetSlack)
	mux.HandleFunc("POST /api/v1/tenant/slack", withMutationRole(auth.RoleAdmin, s.handleSaveSlack))

	// Logical environments (aggregate physical environments)
	mux.HandleFunc("GET /api/v1/logical-environments", s.handleListLogicalEnv)
	mux.HandleFunc("POST /api/v1/logical-environments", withMutationRole(auth.RoleAdmin, s.handleCreateLogicalEnv))
	mux.HandleFunc("POST /api/v1/logical-environments/{id}/members", withMutationRole(auth.RoleAdmin, s.handleAddLogicalMember))
	mux.HandleFunc("DELETE /api/v1/logical-environments/{id}/members/{envId}", withMutationRole(auth.RoleAdmin, s.handleRemoveLogicalMember))
	mux.HandleFunc("GET /api/v1/logical-environments/{id}/state", s.handleLogicalEnvState)

	// Environment policies (required attestation types, tag-conditional) + tags
	mux.HandleFunc("GET /api/v1/environments/{id}/policies", s.handleListEnvPolicies)
	mux.HandleFunc("POST /api/v1/environments/{id}/policies", withMutationRole(auth.RoleAdmin, s.handleCreatePolicy))
	mux.HandleFunc("DELETE /api/v1/environments/{id}/policies/{policyId}", withMutationRole(auth.RoleAdmin, s.handleDeletePolicy))
	mux.HandleFunc("GET /api/v1/environments/{id}/policy-check", s.handlePolicyCheck)
	mux.HandleFunc("POST /api/v1/environments/{id}/tags", withMutationRole(auth.RoleAdmin, s.handleSetEnvTags))
	mux.HandleFunc("POST /api/v1/flows/{id}/tags", withMutationRole(auth.RoleAdmin, s.handleSetFlowTags))

	// Per-environment artifact allow-list (explicit approvals)
	mux.HandleFunc("GET /api/v1/environments/{id}/allowlist", s.handleListAllowlist)
	mux.HandleFunc("POST /api/v1/environments/{id}/allowlist", withMutationRole(auth.RoleAdmin, s.handleAddAllowlist))
	mux.HandleFunc("DELETE /api/v1/environments/{id}/allowlist/{sha}", withMutationRole(auth.RoleAdmin, s.handleRemoveAllowlist))

	// Policy-driven auto-remediation (proposed -> approved|rejected -> applied),
	// gated by an approval record before an action can be applied (issue #235).
	mux.HandleFunc("POST /api/v1/remediation", withMutationRole(auth.RoleWriter, s.handleProposeRemediation))
	mux.HandleFunc("GET /api/v1/remediation", s.handleListRemediation)
	mux.HandleFunc("GET /api/v1/remediation/{id}", s.handleGetRemediation)
	mux.HandleFunc("POST /api/v1/remediation/{id}/approve", withMutationRole(auth.RoleAdmin, s.handleApproveRemediation))
	mux.HandleFunc("POST /api/v1/remediation/{id}/reject", withMutationRole(auth.RoleAdmin, s.handleRejectRemediation))
	mux.HandleFunc("POST /api/v1/remediation/{id}/apply", withMutationRole(auth.RoleAdmin, s.handleApplyRemediation))

	// Artifact API
	mux.HandleFunc("POST /api/v1/artifacts", withMutationRole(auth.RoleWriter, s.handleReportArtifact))
	mux.HandleFunc("GET /api/v1/artifacts", s.handleListArtifacts)

	// Attestation Type API
	mux.HandleFunc("GET /api/v1/attestation-types", s.handleListAttestationTypes)
	mux.HandleFunc("POST /api/v1/attestation-types", withMutationRole(auth.RoleAdmin, s.handleCreateAttestationType))
	mux.HandleFunc("GET /api/v1/attestation-types/{id}", s.handleGetAttestationType)
	mux.HandleFunc("PATCH /api/v1/attestation-types/{id}", withMutationRole(auth.RoleAdmin, s.handlePatchAttestationType))
	mux.HandleFunc("DELETE /api/v1/attestation-types/{id}", withMutationRole(auth.RoleAdmin, s.handleDeleteAttestationType))

	// Attestation API
	mux.HandleFunc("POST /api/v1/attestations", withMutationRole(auth.RoleWriter, s.handleReportAttestation))

	// Snapshot API
	mux.HandleFunc("POST /api/v1/snapshots", withMutationRole(auth.RoleWriter, s.handleReportSnapshot))

	// Compliance and Drift API
	mux.HandleFunc("GET /api/v1/compliance", s.handleCheckCompliance)
	mux.HandleFunc("GET /api/v1/environments", s.handleListEnvironments)
	mux.HandleFunc("POST /api/v1/environments", withMutationRole(auth.RoleAdmin, s.handleCreateEnvironment))
	mux.HandleFunc("GET /api/v1/environments/{id}", s.handleGetEnvironment)
	mux.HandleFunc("PATCH /api/v1/environments/{id}", withMutationRole(auth.RoleAdmin, s.handleUpdateEnvironment))
	mux.HandleFunc("POST /api/v1/environments/{id}/archive", s.handleArchiveEnvironment)
	mux.HandleFunc("POST /api/v1/environments/{id}/unarchive", s.handleUnarchiveEnvironment)
	mux.HandleFunc("GET /api/v1/environments/export", s.handleExportEnvironmentAudit)
	mux.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	mux.HandleFunc("POST /api/v1/policies", withMutationRole(auth.RoleAdmin, s.handleSavePolicy))
	mux.HandleFunc("POST /api/v1/policies/create", s.handleCreatePolicyGlobal)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", s.handleDeletePolicyGlobal)
	mux.HandleFunc("GET /api/v1/ai-assessments", s.handleListAIAssessments)

	// Tenant Webhooks (signed outbound delivery)
	mux.HandleFunc("GET /api/v1/tenant/webhooks", s.handleListWebhooks)
	mux.HandleFunc("POST /api/v1/tenant/webhooks", withMutationRole(auth.RoleAdmin, s.handleSaveWebhook))

	// Tenant Git Providers (CI/CD commit-status gating)
	mux.HandleFunc("GET /api/v1/tenant/git-providers", s.handleListGitProviders)
	mux.HandleFunc("POST /api/v1/tenant/git-providers", withMutationRole(auth.RoleAdmin, s.handleSaveGitProvider))

	// Ingest platform-native attestations (GitHub Artifact Attestations,
	// GitLab Attestations) for a built artifact, using the tenant's configured
	// git-provider token, and record them onto the matching trail/artifact.
	mux.HandleFunc("POST /api/v1/attest/fetch", withMutationRole(auth.RoleWriter, s.handleAttestFetch))

	// Tenant ServiceNow settings (CMDB/ITOM/ITSM)
	mux.HandleFunc("GET /api/v1/tenant/servicenow", s.handleGetServiceNow)
	mux.HandleFunc("POST /api/v1/tenant/servicenow", withMutationRole(auth.RoleAdmin, s.handleSaveServiceNow))
	mux.HandleFunc("GET /api/v1/tenant/servicenow/events", s.handleServiceNowEvents)

	// Assurance console summary — powers the source-owned portal frontpage
	// (portal/src/app/(portal)/page.tsx). The Go-served HTML pages that used to
	// live here (/console, /admin, /servicenow, /evidence) were removed after the
	// portal cutover; only their backing APIs remain.
	mux.HandleFunc("GET /api/v1/console/summary", s.handleConsoleSummary)
	mux.HandleFunc("GET /api/v1/console/stream", s.handleConsoleStream)

	// ITSM change-control gate: fetch a ServiceNow change request and record a
	// servicenow-change attestation evaluated against its jq rules.
	mux.HandleFunc("POST /api/v1/servicenow/change-check", withMutationRole(auth.RoleWriter, s.handleServiceNowChangeCheck))
	mux.HandleFunc("POST /api/v1/servicenow/change-gate", withMutationRole(auth.RoleWriter, s.handleServiceNowChangeGate))

	// Change<->Control linkage (#227): record that a ServiceNow change implemented
	// a Fides control via a specific attestation, and reference it back on the
	// change_request.
	mux.HandleFunc("POST /api/v1/servicenow/link-control", withMutationRole(auth.RoleAdmin, s.handleServiceNowLinkControl))

	// Inbound CI/CD webhooks: auto-create a trail from a signed push event.
	// Public: authenticated by the provider's HMAC/token signature, not a bearer.
	mux.HandleFunc("POST /api/v1/webhooks/{provider}", s.handleInboundWebhook)
	// Feature-flag change governance: record a flag change as a flag.changed
	// attestation on a trail (epic #286 / #287).
	mux.HandleFunc("POST /api/v1/flags/changed", withMutationRole(auth.RoleWriter, s.handleRecordFlagChange))
	// Provider webhook adapters (Unleash/Flagsmith) -> flag.changed (#290).
	mux.HandleFunc("POST /api/v1/flags/webhook/{provider}", withMutationRole(auth.RoleWriter, s.handleFlagWebhook))
	// Flag-change history for auditors + the /admin console (#291).
	mux.HandleFunc("GET /api/v1/flags/history", s.handleFlagHistory)

	// ServiceNow read/action endpoints (backing the MCP tools)
	mux.HandleFunc("GET /api/v1/servicenow/change-status", s.handleServiceNowChangeStatus)
	mux.HandleFunc("POST /api/v1/servicenow/incident", withMutationRole(auth.RoleWriter, s.handleServiceNowCreateIncident))
	mux.HandleFunc("GET /api/v1/servicenow/cmdb", s.handleServiceNowSearchCMDB)

	// Deployment provenance anchoring: on change close / deploy, attach the
	// signed deployment attestation (image digest, commit, build log ref,
	// runtime snapshot ref) to the relevant CMDB CI.
	mux.HandleFunc("POST /api/v1/servicenow/deployment-anchor", withMutationRole(auth.RoleWriter, s.handleServiceNowAnchorDeployment))

	// Now Assist grounding: authoritative control-coverage + evidence for a change.
	mux.HandleFunc("GET /api/v1/servicenow/grounding", s.handleServiceNowGrounding)

	// Fides as a remote MCP server (Streamable HTTP) for Now Assist / AI clients.
	mux.HandleFunc("POST /api/v1/mcp", s.handleMCPServer)

	// ServiceNow MCP client: consume ServiceNow's Model Context Protocol server
	// (discover servers, governed record lookup, list/call tools).
	mux.HandleFunc("GET /api/v1/servicenow/mcp/servers", s.handleSNMCPServers)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/lookup", s.handleSNMCPLookup)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/tools", s.handleSNMCPTools)
	mux.HandleFunc("POST /api/v1/servicenow/mcp/call", withMutationRole(auth.RoleAdmin, s.handleSNMCPCall))

	// Kubernetes ValidatingAdmissionWebhook (deploy-time gate). Public: the API
	// server authenticates via mTLS (configure a CA bundle + NetworkPolicy).
	mux.HandleFunc("POST /api/v1/admission/validate", s.handleAdmissionValidate)

	// Environment MCP Connections API
	mux.HandleFunc("GET /api/v1/environments/mcp", s.handleListEnvironmentMCPServers)
	mux.HandleFunc("POST /api/v1/environments/mcp", withMutationRole(auth.RoleAdmin, s.handleSaveEnvironmentMCPServer))
	mux.HandleFunc("POST /api/v1/environments/mcp/query", s.handleQueryEnvironmentMCPServer)
	mux.HandleFunc("POST /api/v1/environments/mcp/verify", withMutationRole(auth.RoleWriter, s.handleVerifyEnvironmentCompliance))

	// Tenant Settings & SSO APIs
	mux.HandleFunc("GET /api/v1/tenant/settings", s.handleGetTenantSettings)
	mux.HandleFunc("POST /api/v1/tenant/settings", withMutationRole(auth.RoleAdmin, s.handleSaveTenantSettings))
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
	mux.HandleFunc("POST /api/v1/tenant/group-mappings", withMutationRole(auth.RoleAdmin, s.handleSaveGroupMapping))

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
	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	query := `SELECT id, name, COALESCE(description, '') AS description, created_at /* page keys */
	          FROM organizations WHERE id = $1`
	rows, err := s.queryPage(r, page, query, orgID)
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

	page.write(w, list)
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
	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	query := `SELECT id, org_id, name, COALESCE(description, '') AS description, tags, created_at, updated_at /* page keys */
		FROM flows WHERE org_id = $1 AND strpos(lower(name), lower($2)) > 0`
	rows, err := s.queryPage(r, page, query, orgID, r.URL.Query().Get("name"))
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

	page.write(w, list)
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

	op, r := s.beginRecording(w, r, req, false)
	if op == nil {
		return
	}
	defer op.rollback()

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

	op.created(w, r.Context(), trail)
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
