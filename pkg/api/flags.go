package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/events"
)

// FlagChangedAttestationType is the well-known attestation type recorded when a
// software feature flag changes, so flag changes become first-class governed
// evidence — the change gate, segregation-of-duties, and audit trail all apply
// (epic #286, issue #287). Fides is the system-of-record for flag *changes*, not
// a flag-evaluation engine.
const FlagChangedAttestationType = "flag.changed"

// flagFlowName is the auto-created flow that groups an org's flag-change trails.
const flagFlowName = "feature-flags"

type flagChangedReq struct {
	FlowID      string         `json:"flow_id"` // optional; defaults to the org's "feature-flags" flow
	FlagKey     string         `json:"flag_key"`
	Environment string         `json:"environment"`
	OldState    string         `json:"old_state"`
	NewState    string         `json:"new_state"`
	Actor       string         `json:"actor"`
	Source      string         `json:"source"` // e.g. "unleash", "flagsmith", "manual"
	Targeting   map[string]any `json:"targeting"`
}

// handleRecordFlagChange records a feature-flag change as a flag.changed
// attestation on a per-change trail, chaining it into the tamper-evidence ledger
// and emitting a flag.changed event. A control requiring flag.changed (#288)
// then gates deploys on it, and the change is auditable like any other evidence.
// POST /api/v1/flags/changed
func (s *Server) handleRecordFlagChange(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req flagChangedReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	req.FlagKey = strings.TrimSpace(req.FlagKey)
	if req.FlagKey == "" {
		http.Error(w, "flag_key is required", http.StatusBadRequest)
		return
	}

	flowID, err := s.resolveFlagFlow(r.Context(), orgID, req.FlowID)
	if err != nil {
		badRequest(w, err)
		return
	}

	// One trail per flag change (unique name), carrying the flag.changed evidence.
	trailID := uuid.New()
	trailName := req.FlagKey + ":" + req.Environment + ":" + trailID.String()[:8]
	msg := "flag " + req.FlagKey + " [" + req.Environment + "] " + req.OldState + " -> " + req.NewState
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO trails (id, flow_id, name, git_message, tags, created_at)
		 VALUES ($1,$2,$3,$4,$5, now())`,
		trailID, flowID, trailName, msg, marshalJSONB(map[string]string{"actor": req.Actor, "source": req.Source})); err != nil {
		internalError(w, err)
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"flag_key": req.FlagKey, "environment": req.Environment,
		"old_state": req.OldState, "new_state": req.NewState,
		"actor": req.Actor, "source": req.Source, "targeting": req.Targeting,
	})

	// Compliance is policy-driven: any JQ rules registered for the flag.changed
	// attestation type govern the change (e.g. "prod flips must name an actor" or
	// "a >50% rollout must be approved"). A non-compliant flag.changed then fails
	// the change gate on this trail (#288). No rules registered => compliant.
	compliant, err := s.evaluateAttestationTypeCompliance(r.Context(), orgID, FlagChangedAttestationType, string(payload))
	if err != nil {
		internalError(w, err)
		return
	}

	contentHash, prevHash, err := s.attestationChain(r.Context(), trailID, FlagChangedAttestationType, FlagChangedAttestationType, string(payload), compliant)
	if err != nil {
		internalError(w, err)
		return
	}
	attID := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO attestations (id, trail_id, name, type_name, payload, is_compliant, content_hash, prev_hash, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())`,
		attID, trailID, FlagChangedAttestationType, FlagChangedAttestationType, string(payload), compliant, contentHash, prevHash); err != nil {
		internalError(w, err)
		return
	}

	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, "flag.changed", json.RawMessage(payload)); err != nil {
			log.Printf("enqueue flag.changed: %v", err)
		}
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"trail_id": trailID, "attestation_id": attID, "flag_key": req.FlagKey})
}

// resolveFlagFlow returns the flow to record flag changes under: the caller's
// flow_id, or a find-or-created "feature-flags" flow for the org.
func (s *Server) resolveFlagFlow(ctx context.Context, orgID uuid.UUID, flowID string) (uuid.UUID, error) {
	if flowID != "" {
		id, err := uuid.Parse(flowID)
		if err != nil {
			return uuid.UUID{}, err
		}
		// Verify the flow belongs to the caller's org — never trust a request-body
		// id (there is no RLS backstop; this is the tenant boundary). Without this,
		// a caller could inject a flag.changed attestation into another org's trail.
		var owned bool
		if err := s.q(ctx).QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM flows WHERE id = $1 AND org_id = $2)`, id, orgID).Scan(&owned); err != nil {
			return uuid.UUID{}, err
		}
		if !owned {
			return uuid.UUID{}, fmt.Errorf("flow not found")
		}
		return id, nil
	}
	var id uuid.UUID
	err := s.q(ctx).QueryRowContext(ctx,
		`INSERT INTO flows (id, org_id, name, description)
		 VALUES ($1,$2,$3,'Feature-flag change governance')
		 ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, uuid.New(), orgID, flagFlowName).Scan(&id)
	return id, err
}

// evaluateAttestationTypeCompliance evaluates the JQ rules (if any) registered
// for an attestation type against a payload, returning whether it is compliant.
// A type with no registered rules defaults to compliant. This mirrors the
// compliance evaluation the generic attestation-record path performs, so
// flag.changed (and any other well-known type recorded outside that path) can be
// governed by per-org JQ policy rules.
func (s *Server) evaluateAttestationTypeCompliance(ctx context.Context, orgID uuid.UUID, typeName, payload string) (bool, error) {
	var rules []string
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT jq_rules FROM attestation_types WHERE org_id = $1 AND name = $2 LIMIT 1`, orgID, typeName).Scan(pq.Array(&rules))
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if len(rules) == 0 {
		return true, nil
	}
	ok, _, err := s.PolicyEngine.EvaluateAttestation(payload, rules)
	if err != nil {
		return false, err
	}
	return ok, nil
}
