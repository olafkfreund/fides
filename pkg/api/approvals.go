package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
)

func approverIdentity(p *auth.Principal) string {
	if p.Email != "" {
		return p.Email
	}
	if p.UserID != uuid.Nil {
		return p.UserID.String()
	}
	return "service-account"
}

// delegationOutcome is the resolved verdict for an on_behalf_of request. It is
// computed by resolveApprovalDelegation from the server config gate and the
// authenticated principal — deliberately DB-free so it is unit-testable.
type delegationOutcome struct {
	// requested is true when a non-empty on_behalf_of value was supplied.
	requested bool
	// honored is true only when delegation is enabled AND the caller is an
	// authorized service principal. When false, on_behalf_of MUST be ignored and
	// the approval attributed to the token principal (behave exactly as today).
	honored bool
	// onBehalfOf is the trimmed human identity to attribute the approval to,
	// meaningful only when requested is true.
	onBehalfOf string
}

// delegatedApprovalEnabled reports whether on-behalf-of approval delegation is
// switched on server-side. Default-deny: only "true" enables it.
func delegatedApprovalEnabled() bool {
	return os.Getenv("FIDES_DELEGATED_APPROVAL_ENABLED") == "true"
}

// resolveApprovalDelegation decides whether an on_behalf_of value may be
// honored. Secure by default: a delegated approval is honored ONLY when
//   - delegation is explicitly enabled via config, AND
//   - the authenticated principal is a service token (Kind=="service") holding
//     the Admin role.
//
// Any other case (flag off, human session, non-admin service account, empty
// value) leaves honored=false so the caller is never silently upgraded from a
// service token to a human session.
func resolveApprovalDelegation(enabled bool, p *auth.Principal, onBehalfOf string) delegationOutcome {
	v := strings.TrimSpace(onBehalfOf)
	if v == "" {
		return delegationOutcome{}
	}
	honored := enabled && p != nil && p.Kind == "service" && p.Role == auth.RoleAdmin
	return delegationOutcome{requested: true, honored: honored, onBehalfOf: v}
}

// validApproverIdentity reports whether s is a syntactically-valid bare email
// identity (no display name, no angle brackets). Used to validate on_behalf_of.
func validApproverIdentity(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return false
	}
	// mail.ParseAddress also accepts `Name <e@x>`; require the bare address so a
	// delegated identity cannot smuggle a display name into approved_by.
	return addr.Address == s
}

// handleRecordApproval records a segregation-of-duties approval on a trail by the
// authenticated principal (a human session or a machine service account).
//
// It optionally accepts on_behalf_of to record a real human approval attributed
// to a logged-in user when the caller is a shared service token (the SARC portal
// case). Delegation is default-deny and gated by FIDES_DELEGATED_APPROVAL_ENABLED
// plus an Admin service principal; see resolveApprovalDelegation.
func (s *Server) handleRecordApproval(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	var req struct {
		Reason string `json:"reason"`
		// Role distinguishes the segregation-of-duties role this approval
		// represents: "approver" (default, a reviewer sign-off) or "deployer"
		// (the identity that will trigger/perform the deployment).
		Role string `json:"role"`
		// OnBehalfOf, when set and honored, attributes this approval to a human
		// approver (email) rather than the calling service token. Honored only
		// under the config + role gate (see resolveApprovalDelegation).
		OnBehalfOf string `json:"on_behalf_of"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	role := strings.TrimSpace(strings.ToLower(req.Role))
	if role == "" {
		role = "approver"
	}
	if role != "approver" && role != "deployer" {
		http.Error(w, "role must be 'approver' or 'deployer'", http.StatusBadRequest)
		return
	}

	// Resolve delegation. Default identity is the authenticated principal.
	approver := approverIdentity(p)
	kind := p.Kind
	var delegatedBy any // nil => SQL NULL

	del := resolveApprovalDelegation(delegatedApprovalEnabled(), p, req.OnBehalfOf)
	if del.honored {
		// A delegated approval is being recorded — validate the target identity.
		if !validApproverIdentity(del.onBehalfOf) {
			http.Error(w, "on_behalf_of must be a valid email identity", http.StatusBadRequest)
			return
		}
		// Prefer proof that the identity is a real user in this org.
		var known bool
		if err := s.q(r.Context()).QueryRowContext(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM users WHERE org_id = $1 AND lower(email) = lower($2))`,
			p.OrgID, del.onBehalfOf).Scan(&known); err != nil {
			internalError(w, err)
			return
		}
		if !known {
			http.Error(w, "on_behalf_of does not match a known user in the organization", http.StatusBadRequest)
			return
		}
		// Honor the delegation: attribute to the human, record the delegating
		// service principal for audit, and emit an audit trail entry.
		delegatingPrincipal := approverIdentity(p)
		approver = del.onBehalfOf
		kind = "session"
		delegatedBy = delegatingPrincipal
		log.Printf("delegated approval: delegated_by=%q on_behalf_of=%q trail=%s org=%s role=%s",
			delegatingPrincipal, approver, trailID, p.OrgID, role)
	}

	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO trail_approvals (org_id, trail_id, approved_by, approver_kind, reason, role, delegated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (trail_id, approved_by) DO UPDATE SET reason = EXCLUDED.reason, role = EXCLUDED.role, delegated_by = EXCLUDED.delegated_by, created_at = CURRENT_TIMESTAMP`,
		p.OrgID, trailID, approver, kind, req.Reason, role, delegatedBy); err != nil {
		internalError(w, err)
		return
	}

	resp := map[string]any{"status": "approved", "approved_by": approver, "kind": kind, "role": role}
	if del.honored {
		resp["delegated_by"] = delegatedBy
	}
	// Refresh the segregation-of-duties evidence (committer != approver !=
	// deployer) on every recorded approval. Best-effort: never fails the
	// approval the caller is recording.
	if sod := s.emitSegregationOfDutiesAttestation(r.Context(), p.OrgID, trailID); sod != nil {
		resp["segregation_of_duties"] = sod
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
}

// handleListApprovals lists a trail's approvals.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT approved_by, approver_kind, COALESCE(reason, ''), COALESCE(NULLIF(role, ''), 'approver'), COALESCE(delegated_by, ''), created_at
		 FROM trail_approvals WHERE trail_id = $1 AND org_id = $2 ORDER BY created_at`, trailID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var by, kind, reason, role, delegatedBy string
		var created time.Time
		if err := rows.Scan(&by, &kind, &reason, &role, &delegatedBy, &created); err != nil {
			internalError(w, err)
			return
		}
		entry := map[string]any{"approved_by": by, "approver_kind": kind, "reason": reason, "role": role, "created_at": created}
		if delegatedBy != "" {
			entry["delegated_by"] = delegatedBy
		}
		out = append(out, entry)
	}
	writeJSON(w, out)
}
