package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/events"
	"fides/pkg/mcp"
	"fides/pkg/models"
)

// Environment handlers: the runtime side of the picture.
//
// An environment is a place things run. These handlers answer what is running
// there, whether it matches what was approved, and which MCP sensors Fides
// should ask.

type createEnvironmentReq struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // Includes docker, k8s, ecs, lambda, cloud-run, azure-apps, s3 and server.
	Description string `json:"description"`
}

// handleCreateEnvironment creates (or upserts by name) an environment for the
// caller's org. Idempotent on (org_id, name) so re-running a setup script or the
// reporter bootstrap is safe. Create-only callers opt out of the upsert.
func (s *Server) handleCreateEnvironment(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req createEnvironmentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Type) == "" {
		http.Error(w, "name and type are required", http.StatusBadRequest)
		return
	}
	var id uuid.UUID
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`INSERT INTO environments (id, org_id, name, type, description)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (org_id, name) DO UPDATE
		 SET type = EXCLUDED.type, description = EXCLUDED.description, archived = FALSE
		 WHERE NOT $6
		 RETURNING id`,
		uuid.New(), orgID, req.Name, req.Type, req.Description, r.URL.Query().Get("create_only") == "true").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "environment name already exists", http.StatusConflict)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id": id, "name": req.Name, "type": req.Type, "description": req.Description,
	})
}

type environmentRecord struct {
	createEnvironmentReq
	ID       uuid.UUID `json:"id"`
	Archived bool      `json:"archived"`
}

func (s *Server) handleGetEnvironment(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	row := s.q(ctx).QueryRowContext(ctx, `
		SELECT id, name, type, COALESCE(description, ''), archived
		FROM environments WHERE id = $1 AND org_id = $2`, id, orgID)
	writeEnvironmentRecord(w, row)
}

func (s *Server) handleUpdateEnvironment(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Type        *string `json:"type"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if (req.Name != nil && strings.TrimSpace(*req.Name) == "") ||
		(req.Type != nil && strings.TrimSpace(*req.Type) == "") {
		http.Error(w, "name and type cannot be blank", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	row := s.q(ctx).QueryRowContext(ctx, `
		UPDATE environments
		SET name = COALESCE($3, name), type = COALESCE($4, type), description = COALESCE($5, description)
		WHERE id = $1 AND org_id = $2
		RETURNING id, name, type, COALESCE(description, ''), archived`,
		id, orgID, req.Name, req.Type, req.Description)
	writeEnvironmentRecord(w, row)
}

func writeEnvironmentRecord(w http.ResponseWriter, row *sql.Row) {
	var env environmentRecord
	var pqErr *pq.Error
	err := row.Scan(&env.ID, &env.Name, &env.Type, &env.Description, &env.Archived)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "environment not found", http.StatusNotFound)
	case errors.As(err, &pqErr) && pqErr.Code == "23505":
		http.Error(w, "environment name already exists", http.StatusConflict)
	case pqErr != nil && pqErr.Code == "22001":
		http.Error(w, "environment name or type is too long", http.StatusBadRequest)
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, env)
	}
}

type environmentRuntimeArtifact struct {
	Service    string `json:"service"`
	SHA256     string `json:"sha256"`
	Registered bool   `json:"registered"`
	Name       string `json:"name"`
}

type environmentView struct {
	ID            string                       `json:"id"`
	Name          string                       `json:"name"`
	Type          string                       `json:"type"`
	Description   string                       `json:"description"`
	LastSnapshot  string                       `json:"lastSnapshot"`
	Running       []environmentRuntimeArtifact `json:"running"`
	Drifts        []string                     `json:"drifts"`
	ShadowChanges []string                     `json:"shadowChanges"`
}

func (s *Server) handleListEnvironments(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	includeArchived := r.URL.Query().Get("include_archived") == "true"
	rows, err := s.queryPage(r, page, `
		SELECT id, name, type, COALESCE(description, ''), archived /* page keys */
		FROM environments WHERE org_id = $1 AND ($2 OR NOT archived)
		  AND strpos(lower(name), lower($3)) > 0`, orgID, includeArchived, r.URL.Query().Get("name"))
	if err != nil {
		internalError(w, err)
		return
	}

	type listedEnvironment struct {
		environmentView
		Archived bool `json:"archived"`
	}

	defer rows.Close()
	list := []*listedEnvironment{}
	byID := map[string]*environmentView{}
	for rows.Next() {
		var ev listedEnvironment
		if err := rows.Scan(&ev.ID, &ev.Name, &ev.Type, &ev.Description, &ev.Archived); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &ev)
		byID[ev.ID] = &ev.environmentView
	}
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	// Finish the base page before enriching it on the request's pinned connection.
	if err := rows.Close(); err != nil {
		internalError(w, err)
		return
	}
	if err := s.enrichEnvironmentDrift(r.Context(), orgID, byID); err != nil {
		internalError(w, err)
		return
	}
	page.write(w, list)
}

func (s *Server) enrichEnvironmentDrift(ctx context.Context, orgID uuid.UUID, byID map[string]*environmentView) error {
	if len(byID) == 0 {
		return nil
	}
	ids := make([]string, 0, len(byID))
	for id, ev := range byID {
		ids = append(ids, id)
		ev.LastSnapshot = "No snapshot reported yet"
		ev.Running = []environmentRuntimeArtifact{}
		ev.Drifts = []string{}
		ev.ShadowChanges = []string{}
	}

	// Match allowlists by the exact reported runtime digest, as snapshot
	// ingestion does, and only check historical approvals for current shadows.
	runtimeRows, err := s.q(ctx).QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (environment_id) environment_id, id, created_at
			FROM environment_snapshots
			WHERE environment_id = ANY($1)
			ORDER BY environment_id, created_at DESC NULLS LAST, id DESC
		), running AS (
			SELECT l.environment_id, sa.id, sa.service_name, sa.runtime_digest, a.name, a.trail_id,
			       (a.sha256 IS NOT NULL) AS registered, (al.id IS NOT NULL) AS approved
			FROM latest l
			JOIN snapshot_artifacts sa ON sa.snapshot_id = l.id
			LEFT JOIN artifacts a ON a.sha256 = sa.artifact_sha256 AND a.org_id = $2
			LEFT JOIN environment_allowlist al ON al.environment_id = l.environment_id
			                                  AND al.artifact_sha256 = sa.runtime_digest
		), prior_approval AS (
			SELECT DISTINCT r.environment_id, r.service_name
			FROM running r
			JOIN environment_snapshots s ON s.environment_id = r.environment_id
			JOIN snapshot_artifacts sa ON sa.snapshot_id = s.id AND sa.service_name = r.service_name
			JOIN environment_allowlist al ON al.environment_id = s.environment_id
			                             AND al.artifact_sha256 = sa.runtime_digest
			WHERE NOT r.registered AND NOT r.approved AND r.service_name <> ''
		), trail_results AS (
			SELECT at.trail_id, bool_or(NOT at.is_compliant) AS failing
			FROM (SELECT DISTINCT trail_id FROM running WHERE trail_id IS NOT NULL) rt
			JOIN trails tr ON tr.id = rt.trail_id
			JOIN flows f ON f.id = tr.flow_id AND f.org_id = $2
			JOIN attestations at ON at.trail_id = tr.id
			GROUP BY at.trail_id
		)
		SELECT l.environment_id, l.created_at, r.service_name, r.runtime_digest, r.registered,
		       COALESCE(r.name, ''), r.approved, (p.service_name IS NOT NULL), COALESCE(t.failing, false)
		FROM latest l
		LEFT JOIN running r ON r.environment_id = l.environment_id
		LEFT JOIN prior_approval p ON p.environment_id = r.environment_id AND p.service_name = r.service_name
		LEFT JOIN trail_results t ON t.trail_id = r.trail_id
		ORDER BY r.service_name, r.id`, pq.Array(ids), orgID)
	if err != nil {
		return err
	}
	defer runtimeRows.Close()
	for runtimeRows.Next() {
		var envID string
		var snapshot sql.NullTime
		var service, digest sql.NullString
		var registered, approved sql.NullBool
		var priorApproval, failing bool
		var artifact environmentRuntimeArtifact
		if err := runtimeRows.Scan(&envID, &snapshot, &service, &digest, &registered, &artifact.Name, &approved, &priorApproval, &failing); err != nil {
			return err
		}
		ev := byID[envID]
		if snapshot.Valid {
			ev.LastSnapshot = snapshot.Time.Format("2006-01-02 15:04:05")
		}
		if !service.Valid {
			continue
		}
		artifact.Service, artifact.SHA256, artifact.Registered = service.String, digest.String, registered.Bool
		ev.Running = append(ev.Running, artifact)
		if !artifact.Registered && !approved.Bool {
			ev.ShadowChanges = append(ev.ShadowChanges, shadowMessage(artifact.Service, artifact.SHA256, priorApproval))
		}
		if failing {
			ev.Drifts = append(ev.Drifts, fmt.Sprintf("service %s running drifted artifact %s (failing controls)", artifact.Service, artifact.SHA256))
		}
	}
	return runtimeRows.Err()
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
	var ev environmentView
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryEnv, envID, orgID).Scan(&ev.ID, &ev.Name, &ev.Type, &ev.Description)
	if err != nil {
		http.Error(w, fmt.Sprintf("environment not found: %v", err), http.StatusNotFound)
		return
	}
	if err := s.enrichEnvironmentDrift(r.Context(), orgID, map[string]*environmentView{ev.ID: &ev}); err != nil {
		internalError(w, err)
		return
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
		// A failed iteration must not read as a short result.
		if err := mcpRows.Err(); err != nil {
			internalError(w, err)
			return
		}
	}

	// Build the report struct
	report := struct {
		Environment environmentView `json:"environment"`
		MCPServers  []MCPServerView `json:"mcp_servers"`
		ExportedAt  string          `json:"exported_at"`
	}{
		Environment: ev,
		MCPServers:  mcpServers,
		ExportedAt:  time.Now().Format(time.RFC3339),
	}

	fileName := fmt.Sprintf("audit-report-%s.json", ev.Name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	json.NewEncoder(w).Encode(report)
}

func (s *Server) handleListEnvironmentMCPServers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
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

	if !s.requireEnvInOrg(w, r, envID) {
		return
	}

	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	query := `SELECT id, environment_id, name, transport, COALESCE(command, ''), args, env_vars, COALESCE(url, ''), COALESCE(auth_header, ''), created_at, updated_at /* page keys */
	          FROM environment_mcp_servers WHERE environment_id = $1`
	rows, err := s.queryPage(r, page, query, envID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	list := []models.EnvironmentMCPServer{}
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
		if err := json.Unmarshal(envVarsBytes, &srv.EnvVars); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, srv)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	page.write(w, list)
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

	if !s.requireEnvInOrg(w, r, req.EnvironmentID) {
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
	if !s.requireEnvInOrg(w, r, envID) {
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
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "MCP server configuration not found for this environment", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	srv.Args = []string(args)
	if err := json.Unmarshal(envVarsBytes, &srv.EnvVars); err != nil {
		internalError(w, err)
		return
	}

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
	fmt.Fprintf(w, `{"result": %q}`, output)
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
	if !s.requireEnvInOrg(w, r, envID) {
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
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "MCP server configuration not found for this environment", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	srv.Args = []string(args)
	if err := json.Unmarshal(envVarsBytes, &srv.EnvVars); err != nil {
		internalError(w, err)
		return
	}

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
	compliant, failedRules, err := s.PolicyEngine.EvaluateAttestation(r.Context(), output, req.Rules)
	if err != nil {
		internalError(w, err)
		return
	}

	// Emit a compliance.evaluated event so a failing runtime check flows to the
	// webhook/Slack/ServiceNow sinks (opt-in via FIDES_EVENTS_ENABLED).
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if orgID, ok := principalOrg(r); ok {
			if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, "compliance.evaluated", map[string]any{
				"environment_id": req.EnvironmentID,
				"server_name":    req.ServerName,
				"tool_name":      req.ToolName,
				"compliant":      compliant,
				"failed_rules":   failedRules,
			}); err != nil {
				log.Printf("failed to enqueue compliance.evaluated (mcp verify): %v", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"compliant":    compliant,
		"failed_rules": failedRules,
		"raw_response": output,
	})
}
