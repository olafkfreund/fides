package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// trailInOrg reports whether a trail belongs to an org.
//
// Trails carry no org_id of their own — ownership is the parent flow's, so the
// question can only be answered through the join.
func (s *Server) trailInOrg(ctx context.Context, trailID, orgID uuid.UUID) (bool, error) {
	var owned bool
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM trails tr JOIN flows f ON f.id = tr.flow_id
		 WHERE tr.id = $1 AND f.org_id = $2)`, trailID, orgID).Scan(&owned)
	return owned, err
}

// requireTrailInOrg refuses a trail id that does not belong to the caller.
//
// Trail ids arrive from a path segment or a request body, so they are
// attacker-chosen, and there is no RLS backstop worth relying on here: RLS is
// opt-in behind FIDES_RLS_ENABLED, so on a default deployment an unchecked
// trail id is simply honoured. Handlers that read a trail's chain, evaluate its
// gate, or append an attestation to it must ask this first.
//
// 404 rather than 403: a tenant should not learn that another tenant's trail
// id exists.
func (s *Server) requireTrailInOrg(w http.ResponseWriter, r *http.Request, trailID uuid.UUID) bool {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	owned, err := s.trailInOrg(r.Context(), trailID, orgID)
	if err != nil {
		internalError(w, err)
		return false
	}
	if !owned {
		http.Error(w, "trail not found", http.StatusNotFound)
		return false
	}
	return true
}

// flowInOrg reports whether a flow belongs to an org.
func (s *Server) flowInOrg(ctx context.Context, flowID, orgID uuid.UUID) (bool, error) {
	var owned bool
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM flows WHERE id = $1 AND org_id = $2)`, flowID, orgID).Scan(&owned)
	return owned, err
}

// requireFlowInOrg refuses a flow id that does not belong to the caller.
//
// Creating a trail names its parent flow, so without this a tenant can plant a
// build record in another tenant's provenance — the flow id is the only thing
// tying the trail to an org.
func (s *Server) requireFlowInOrg(w http.ResponseWriter, r *http.Request, flowID uuid.UUID) bool {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	owned, err := s.flowInOrg(r.Context(), flowID, orgID)
	if err != nil {
		internalError(w, err)
		return false
	}
	if !owned {
		http.Error(w, "flow not found", http.StatusNotFound)
		return false
	}
	return true
}
