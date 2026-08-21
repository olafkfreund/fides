package api

import (
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
	Type        string `json:"type"` // docker | k8s | ecs | lambda | s3 | server
	Description string `json:"description"`
}

// handleCreateEnvironment creates (or upserts by name) an environment for the
// caller's org. Idempotent on (org_id, name) so re-running a setup script or the
// reporter bootstrap is safe. Tenant scope comes from the principal (H2/IDOR).
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
		 -- Re-registering an environment by name un-archives it. Creating one is
		 -- a statement that it is in use, and the alternative is a silent trap:
		 -- the caller gets 201 and an id, then wonders why it is absent from
		 -- coverage and from the environment list.
		 ON CONFLICT (org_id, name) DO UPDATE SET type = EXCLUDED.type, description = EXCLUDED.description, archived = FALSE
		 RETURNING id`,
		uuid.New(), orgID, req.Name, req.Type, req.Description).Scan(&id)
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

func (s *Server) handleListEnvironments(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Archived environments are hidden unless asked for. Retiring one is meant
	// to get it out of the way; leaving it listed would only move the clutter
	// from the coverage number to the page.
	queryEnv := `SELECT id, name, type, COALESCE(description, '') AS description, archived
	             FROM environments WHERE org_id = $1 AND NOT archived`
	if r.URL.Query().Get("include_archived") == "true" {
		queryEnv = `SELECT id, name, type, COALESCE(description, '') AS description, archived
		            FROM environments WHERE org_id = $1`
	}
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
		Archived      bool              `json:"archived"`
		LastSnapshot  string            `json:"lastSnapshot"`
		Running       []RuntimeArtifact `json:"running"`
		Drifts        []string          `json:"drifts"`
		ShadowChanges []string          `json:"shadowChanges"`
	}

	// Collect all base environments FIRST. Under RLS, s.q(ctx) is a single
	// pinned connection, so we must drain this cursor before running any
	// sub-query — otherwise the nested query disrupts the outer cursor and only
	// the first row is returned.
	list := []*EnvironmentView{}
	for rows.Next() {
		var ev EnvironmentView
		if err := rows.Scan(&ev.ID, &ev.Name, &ev.Type, &ev.Description, &ev.Archived); err != nil {
			rows.Close()
			internalError(w, err)
			return
		}
		ev.LastSnapshot = "No snapshot reported yet"
		ev.Running = []RuntimeArtifact{}
		ev.Drifts = []string{}
		ev.ShadowChanges = []string{}
		list = append(list, &ev)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		rows.Close()
		internalError(w, err)
		return
	}
	rows.Close()

	// Enrich each environment now that the outer cursor is closed.
	for _, ev := range list {
		var latestSnapID string
		var snapTime time.Time
		querySnap := `SELECT id, created_at FROM environment_snapshots WHERE environment_id = $1 ORDER BY created_at DESC LIMIT 1`
		if err := s.q(r.Context()).QueryRowContext(r.Context(), querySnap, ev.ID).Scan(&latestSnapID, &snapTime); err != nil {
			continue
		}
		ev.LastSnapshot = snapTime.Format("2006-01-02 15:04:05")

		// Read all running artifacts into memory before the per-artifact queries.
		querySA := `SELECT sa.service_name, sa.runtime_digest, (sa.artifact_sha256 IS NOT NULL), COALESCE(a.name, '')
		            FROM snapshot_artifacts sa
		            LEFT JOIN artifacts a ON sa.artifact_sha256 = a.sha256
		            WHERE sa.snapshot_id = $1`
		saRows, err := s.q(r.Context()).QueryContext(r.Context(), querySA, latestSnapID)
		if err != nil {
			defer saRows.Close()
			continue
		}
		var running []RuntimeArtifact
		for saRows.Next() {
			var ra RuntimeArtifact
			if err := saRows.Scan(&ra.Service, &ra.SHA256, &ra.Registered, &ra.Name); err == nil {
				running = append(running, ra)
			}
		}
		// A failed iteration must not read as a short result.
		if err := saRows.Err(); err != nil {
			internalError(w, err)
			return
		}
		saRows.Close()

		for _, ra := range running {
			ev.Running = append(ev.Running, ra)
			if !ra.Registered {
				ev.ShadowChanges = append(ev.ShadowChanges, fmt.Sprintf("service %s running unregistered digest %s", ra.Service, ra.SHA256))
				continue
			}
			var trailID sql.NullString
			// No row is the ordinary case -- the artifact is simply not
			// registered. A real error is not, and swallowing it here silently
			// under-reports drift, which is the one direction a compliance view
			// must not fail in.
			if err := s.q(r.Context()).QueryRowContext(r.Context(),
				"SELECT trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1", ra.SHA256, orgID).Scan(&trailID); err != nil && !errors.Is(err, sql.ErrNoRows) {
				internalError(w, err)
				return
			}
			if trailID.Valid {
				var compliantCount, totalCount int
				if err := s.q(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*), SUM(CASE WHEN is_compliant THEN 1 ELSE 0 END) FROM attestations WHERE trail_id = $1", trailID.String).Scan(&totalCount, &compliantCount); err != nil && !errors.Is(err, sql.ErrNoRows) {
					internalError(w, err)
					return
				}
				if totalCount > 0 && compliantCount < totalCount {
					ev.Drifts = append(ev.Drifts, fmt.Sprintf("service %s running drifted artifact %s (failing controls)", ra.Service, ra.SHA256))
				}
			}
		}
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
		// Read all running artifacts before per-artifact queries — under RLS,
		// s.q(ctx) is a single pinned connection and nested queries would break
		// the outer cursor.
		if saRows, err := s.q(r.Context()).QueryContext(r.Context(), querySA, latestSnapID); err == nil {
			var running []RuntimeArtifact
			defer saRows.Close()
			for saRows.Next() {
				var ra RuntimeArtifact
				if err := saRows.Scan(&ra.Service, &ra.SHA256, &ra.Registered, &ra.Name); err == nil {
					running = append(running, ra)
				}
			}
			// A failed iteration must not read as a short result.
			if err := saRows.Err(); err != nil {
				internalError(w, err)
				return
			}
			saRows.Close()

			for _, ra := range running {
				ev.Running = append(ev.Running, ra)
				if !ra.Registered {
					ev.ShadowChanges = append(ev.ShadowChanges, fmt.Sprintf("service %s running unregistered digest %s", ra.Service, ra.SHA256))
					continue
				}
				var trailID sql.NullString
				if err := s.q(r.Context()).QueryRowContext(r.Context(),
					"SELECT trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1", ra.SHA256, orgID).Scan(&trailID); err != nil && !errors.Is(err, sql.ErrNoRows) {
					internalError(w, err)
					return
				}
				if trailID.Valid {
					var compliantCount, totalCount int
					if err := s.q(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*), SUM(CASE WHEN is_compliant THEN 1 ELSE 0 END) FROM attestations WHERE trail_id = $1", trailID.String).Scan(&totalCount, &compliantCount); err != nil && !errors.Is(err, sql.ErrNoRows) {
						internalError(w, err)
						return
					}
					if totalCount > 0 && compliantCount < totalCount {
						ev.Drifts = append(ev.Drifts, fmt.Sprintf("service %s running drifted artifact %s (failing controls)", ra.Service, ra.SHA256))
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
		// A failed iteration must not read as a short result.
		if err := mcpRows.Err(); err != nil {
			internalError(w, err)
			return
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

	if !s.requireEnvInOrg(w, r, envID) {
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
	compliant, failedRules, err := s.PolicyEngine.EvaluateAttestation(output, req.Rules)
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
