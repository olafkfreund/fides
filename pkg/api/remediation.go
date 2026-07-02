package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/remediation"
)

// Policy-driven auto-remediation with approval gates (issue #235).
//
// Flow: a policy violation is detected (by a human, CI, or another Fides
// mechanism) -> a remediation is proposed via this API -> a distinct
// principal approves it (segregation of duties, mirroring trail approvals)
// -> only then can it be applied. Applying executes the low-risk, additive
// change for the action's domain. Nothing in this file ever mutates
// environment/allowlist state without first checking the action's status is
// Approved (pkg/remediation.Apply enforces this at the state-machine level).

type remediationProposeReq struct {
	Domain        string          `json:"domain"`
	EnvironmentID string          `json:"environment_id"`
	PolicyID      string          `json:"policy_id,omitempty"`
	Reason        string          `json:"reason"`
	Params        json.RawMessage `json:"params"`
}

// validateRemediationParams enforces the minimal shape each domain needs to
// be applied later, so a proposal fails fast rather than at apply time.
func validateRemediationParams(domain remediation.Domain, paramsJSON string) error {
	var params map[string]any
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return fmt.Errorf("params must be a JSON object")
	}
	switch domain {
	case remediation.DomainEnvTag:
		tags, ok := params["tags"].(map[string]any)
		if !ok || len(tags) == 0 {
			return fmt.Errorf("params.tags (a non-empty object) is required for domain %q", domain)
		}
		for k, v := range tags {
			if _, ok := v.(string); !ok || k == "" {
				return fmt.Errorf("params.tags must be a flat map of string keys to string values")
			}
		}
	case remediation.DomainAllowlistEntry, remediation.DomainDriftResync:
		sha, ok := params["artifact_sha256"].(string)
		if !ok || sha == "" {
			return fmt.Errorf("params.artifact_sha256 is required for domain %q", domain)
		}
	default:
		return remediation.ErrInvalidDomain
	}
	return nil
}

// handleProposeRemediation records a new remediation proposal (state:
// proposed). It never mutates environment/allowlist state.
func (s *Server) handleProposeRemediation(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req remediationProposeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	domain := remediation.Domain(req.Domain)
	proposer := approverIdentity(p)
	if _, err := remediation.Propose(domain, proposer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.EnvironmentID == "" {
		http.Error(w, "environment_id is required", http.StatusBadRequest)
		return
	}
	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}
	owned, err := s.envInOrg(r.Context(), envID, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}

	var policyID uuid.NullUUID
	if req.PolicyID != "" {
		pid, err := uuid.Parse(req.PolicyID)
		if err != nil {
			http.Error(w, "invalid policy_id", http.StatusBadRequest)
			return
		}
		var policyOwned bool
		if err := s.q(r.Context()).QueryRowContext(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM policies WHERE id = $1 AND org_id = $2)`, pid, p.OrgID).Scan(&policyOwned); err != nil {
			internalError(w, err)
			return
		}
		if !policyOwned {
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}
		policyID = uuid.NullUUID{UUID: pid, Valid: true}
	}

	params := "{}"
	if len(req.Params) > 0 {
		var v any
		if err := json.Unmarshal(req.Params, &v); err != nil {
			http.Error(w, "params must be valid JSON", http.StatusBadRequest)
			return
		}
		params = string(req.Params)
	}
	if err := validateRemediationParams(domain, params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO remediation_actions (id, org_id, domain, status, environment_id, policy_id, reason, params, proposed_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, p.OrgID, string(domain), string(remediation.StatusProposed), envID, policyID, req.Reason, params, proposer); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id, "status": remediation.StatusProposed, "proposed_by": proposer})
}

type remediationRow struct {
	ID            uuid.UUID
	Domain        string
	Status        string
	EnvironmentID uuid.NullUUID
	PolicyID      uuid.NullUUID
	Reason        string
	Params        string
	ProposedBy    string
	ApprovedBy    string
	AppliedBy     string
	RejectedBy    string
	ResultDetail  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (row remediationRow) toJSON() map[string]any {
	out := map[string]any{
		"id":            row.ID,
		"domain":        row.Domain,
		"status":        row.Status,
		"reason":        row.Reason,
		"params":        json.RawMessage(row.Params),
		"proposed_by":   row.ProposedBy,
		"approved_by":   row.ApprovedBy,
		"applied_by":    row.AppliedBy,
		"rejected_by":   row.RejectedBy,
		"result_detail": row.ResultDetail,
		"created_at":    row.CreatedAt,
		"updated_at":    row.UpdatedAt,
	}
	if row.EnvironmentID.Valid {
		out["environment_id"] = row.EnvironmentID.UUID
	}
	if row.PolicyID.Valid {
		out["policy_id"] = row.PolicyID.UUID
	}
	return out
}

const remediationSelect = `SELECT id, domain, status, environment_id, policy_id, COALESCE(reason,''), params,
	proposed_by, COALESCE(approved_by,''), COALESCE(applied_by,''), COALESCE(rejected_by,''), COALESCE(result_detail,''),
	created_at, updated_at FROM remediation_actions`

func scanRemediationRow(scan func(dest ...any) error) (remediationRow, error) {
	var row remediationRow
	err := scan(&row.ID, &row.Domain, &row.Status, &row.EnvironmentID, &row.PolicyID, &row.Reason, &row.Params,
		&row.ProposedBy, &row.ApprovedBy, &row.AppliedBy, &row.RejectedBy, &row.ResultDetail, &row.CreatedAt, &row.UpdatedAt)
	return row, err
}

// handleListRemediation lists remediation actions for the org, optionally
// filtered by ?status= and/or ?environment_id=.
func (s *Server) handleListRemediation(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := remediationSelect + ` WHERE org_id = $1`
	args := []any{orgID}
	if status := r.URL.Query().Get("status"); status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if envParam := r.URL.Query().Get("environment_id"); envParam != "" {
		envID, err := uuid.Parse(envParam)
		if err != nil {
			http.Error(w, "invalid environment_id", http.StatusBadRequest)
			return
		}
		args = append(args, envID)
		query += fmt.Sprintf(" AND environment_id = $%d", len(args))
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, args...)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		row, err := scanRemediationRow(rows.Scan)
		if err != nil {
			internalError(w, err)
			return
		}
		out = append(out, row.toJSON())
	}
	writeJSON(w, out)
}

// handleGetRemediation fetches a single remediation action.
func (s *Server) handleGetRemediation(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	row, err := scanRemediationRow(s.q(r.Context()).QueryRowContext(r.Context(),
		remediationSelect+` WHERE id = $1 AND org_id = $2`, id, orgID).Scan)
	if err != nil {
		http.Error(w, "remediation action not found", http.StatusNotFound)
		return
	}
	writeJSON(w, row.toJSON())
}

// handleApproveRemediation moves a proposed action to approved. The approver
// must be a distinct principal from the proposer (segregation of duties).
func (s *Server) handleApproveRemediation(w http.ResponseWriter, r *http.Request) {
	s.transitionRemediation(w, r, func(current remediation.Status, proposedBy, actor string) (remediation.Status, error) {
		return remediation.Approve(current, proposedBy, actor)
	}, "approved_by")
}

// handleRejectRemediation moves a proposed action to rejected.
func (s *Server) handleRejectRemediation(w http.ResponseWriter, r *http.Request) {
	s.transitionRemediation(w, r, func(current remediation.Status, _, actor string) (remediation.Status, error) {
		return remediation.Reject(current, actor)
	}, "rejected_by")
}

// transitionRemediation is the shared approve/reject plumbing: load the
// action, run the pure state-machine transition, persist the new status and
// actor column on success.
func (s *Server) transitionRemediation(w http.ResponseWriter, r *http.Request,
	transition func(current remediation.Status, proposedBy, actor string) (remediation.Status, error), actorColumn string) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	var currentStatus, proposedBy string
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT status, proposed_by FROM remediation_actions WHERE id = $1 AND org_id = $2`, id, p.OrgID).
		Scan(&currentStatus, &proposedBy); err != nil {
		http.Error(w, "remediation action not found", http.StatusNotFound)
		return
	}

	actor := approverIdentity(p)
	newStatus, err := transition(remediation.Status(currentStatus), proposedBy, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// actorColumn is one of the two fixed internal constants below, never user input.
	query := fmt.Sprintf(`UPDATE remediation_actions SET status = $1, %s = $2, updated_at = now() WHERE id = $3 AND org_id = $4`, actorColumn)
	if _, err := s.q(r.Context()).ExecContext(r.Context(), query, string(newStatus), actor, id, p.OrgID); err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": newStatus, actorColumn: actor})
}

// handleApplyRemediation executes the action's domain-specific change. It
// refuses unless the action is Approved (pkg/remediation.Apply), so a
// remediation can never be auto-applied without an approval record.
func (s *Server) handleApplyRemediation(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	row, err := scanRemediationRow(s.q(r.Context()).QueryRowContext(r.Context(),
		remediationSelect+` WHERE id = $1 AND org_id = $2`, id, p.OrgID).Scan)
	if err != nil {
		http.Error(w, "remediation action not found", http.StatusNotFound)
		return
	}

	applier := approverIdentity(p)
	newStatus, err := remediation.Apply(remediation.Status(row.Status), applier)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !row.EnvironmentID.Valid {
		http.Error(w, "remediation action has no environment to apply to", http.StatusConflict)
		return
	}

	detail, err := s.applyRemediationDomain(r.Context(), p.OrgID, remediation.Domain(row.Domain), row.EnvironmentID.UUID, row.Params, applier, row.Reason)
	if err != nil {
		internalError(w, err)
		return
	}

	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE remediation_actions SET status = $1, applied_by = $2, result_detail = $3, updated_at = now() WHERE id = $4 AND org_id = $5`,
		string(newStatus), applier, detail, id, p.OrgID); err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": newStatus, "applied_by": applier, "result_detail": detail})
}

// applyRemediationDomain performs the actual low-risk change for a domain.
// Every branch is additive (tag merge / allowlist insert) — nothing here
// deletes or overwrites unrelated state.
func (s *Server) applyRemediationDomain(ctx context.Context, orgID uuid.UUID, domain remediation.Domain, envID uuid.UUID, paramsJSON, actor, reason string) (string, error) {
	var params map[string]any
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return "", fmt.Errorf("invalid stored params: %w", err)
	}

	switch domain {
	case remediation.DomainEnvTag:
		tagsRaw, _ := json.Marshal(params["tags"])
		if _, err := s.q(ctx).ExecContext(ctx,
			`UPDATE environments SET tags = COALESCE(tags, '{}'::jsonb) || $1::jsonb WHERE id = $2 AND org_id = $3`,
			string(tagsRaw), envID, orgID); err != nil {
			return "", err
		}
		return fmt.Sprintf("merged tags %s into environment %s", string(tagsRaw), envID), nil

	case remediation.DomainAllowlistEntry, remediation.DomainDriftResync:
		sha, _ := params["artifact_sha256"].(string)
		note := reason
		if domain == remediation.DomainDriftResync && note == "" {
			note = "drift re-sync: accepted running digest as new baseline"
		}
		if _, err := s.q(ctx).ExecContext(ctx,
			`INSERT INTO environment_allowlist (environment_id, artifact_sha256, approved_by, reason)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (environment_id, artifact_sha256) DO UPDATE SET approved_by = EXCLUDED.approved_by, reason = EXCLUDED.reason, created_at = now()`,
			envID, sha, actor, note); err != nil {
			return "", err
		}
		return fmt.Sprintf("allow-listed digest %s for environment %s", sha, envID), nil

	default:
		return "", remediation.ErrInvalidDomain
	}
}
