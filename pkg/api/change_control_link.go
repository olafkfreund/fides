package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/events"
	"fides/pkg/servicenow"
)

type linkControlReq struct {
	TrailID       string `json:"trail_id"`
	ControlKey    string `json:"control"`
	ChangeNumber  string `json:"change_number"`
	AttestationID string `json:"attestation_id"` // optional; defaults to the trail's most recent attestation
}

// changeControlLink is the Fides-side record of a change<->control linkage,
// independent of whether the ServiceNow write-back succeeded.
type changeControlLink struct {
	TrailID       uuid.UUID
	ControlID     uuid.UUID
	ControlName   string
	AttestationID uuid.UUID
	AttestedAt    time.Time
}

// resolveChangeControlLink resolves the trail, control, and attestation
// referenced by req (all org-scoped). It does not write anything or talk to
// ServiceNow — that happens separately (upsertChangeControlLink,
// servicenow.WriteControlLink) so each concern is independently testable.
func (s *Server) resolveChangeControlLink(ctx context.Context, orgID uuid.UUID, req linkControlReq) (*changeControlLink, int, error) {
	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		return nil, http.StatusBadRequest, errBadRequest("valid trail_id is required")
	}
	if req.ControlKey == "" {
		return nil, http.StatusBadRequest, errBadRequest("control is required")
	}
	if req.ChangeNumber == "" {
		return nil, http.StatusBadRequest, errBadRequest("change_number is required")
	}

	// Trail must belong to the caller's org (via its flow).
	var trailExists bool
	if err := s.q(ctx).QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM trails tr JOIN flows f ON f.id = tr.flow_id WHERE tr.id = $1 AND f.org_id = $2)`,
		trailID, orgID).Scan(&trailExists); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !trailExists {
		return nil, http.StatusNotFound, errBadRequest("trail not found")
	}

	// Control must exist (and be active) in the caller's org.
	var controlID uuid.UUID
	var controlName string
	err = s.q(ctx).QueryRowContext(ctx,
		`SELECT id, name FROM controls WHERE org_id = $1 AND key = $2 AND NOT archived`,
		orgID, req.ControlKey).Scan(&controlID, &controlName)
	if err == sql.ErrNoRows {
		return nil, http.StatusNotFound, errBadRequest("control not found: " + req.ControlKey)
	}
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// Attestation: either the one named explicitly, or the trail's most recent.
	var attestationID uuid.UUID
	var attestedAt time.Time
	if req.AttestationID != "" {
		aid, err := uuid.Parse(req.AttestationID)
		if err != nil {
			return nil, http.StatusBadRequest, errBadRequest("invalid attestation_id")
		}
		err = s.q(ctx).QueryRowContext(ctx,
			`SELECT id, created_at FROM attestations WHERE id = $1 AND trail_id = $2`,
			aid, trailID).Scan(&attestationID, &attestedAt)
		if err == sql.ErrNoRows {
			return nil, http.StatusNotFound, errBadRequest("attestation not found on this trail")
		}
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	} else {
		err = s.q(ctx).QueryRowContext(ctx,
			`SELECT id, created_at FROM attestations WHERE trail_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`,
			trailID).Scan(&attestationID, &attestedAt)
		if err == sql.ErrNoRows {
			return nil, http.StatusNotFound, errBadRequest("trail has no attestations to link as evidence")
		}
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	link := &changeControlLink{
		TrailID:       trailID,
		ControlID:     controlID,
		ControlName:   controlName,
		AttestationID: attestationID,
		AttestedAt:    attestedAt,
	}
	return link, 0, nil
}

// upsertChangeControlLink persists (or updates) the linkage row, recording
// whatever the current ServiceNow write-back outcome was.
func (s *Server) upsertChangeControlLink(ctx context.Context, orgID uuid.UUID, link *changeControlLink, changeNumber, changeSysID, linkedBy string, synced bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.q(ctx).QueryRowContext(ctx,
		`INSERT INTO change_control_links (org_id, trail_id, control_id, attestation_id, change_number, change_sys_id, linked_by, servicenow_synced)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8)
		 ON CONFLICT (trail_id, control_id, change_number) DO UPDATE SET
		   attestation_id = EXCLUDED.attestation_id,
		   change_sys_id = EXCLUDED.change_sys_id,
		   linked_by = EXCLUDED.linked_by,
		   servicenow_synced = EXCLUDED.servicenow_synced,
		   created_at = CURRENT_TIMESTAMP
		 RETURNING id`,
		orgID, link.TrailID, link.ControlID, link.AttestationID, changeNumber, changeSysID, linkedBy, synced).Scan(&id)
	return id, err
}

// handleServiceNowLinkControl records that a ServiceNow change (CHGxxxx)
// implemented a Fides control via a specific attestation, so both the Fides
// linkage record and the ServiceNow change_request (work notes + best-effort
// custom fields) reference the same evidence. The Fides-side record is
// always persisted; the ServiceNow write-back is best-effort (skipped if
// ServiceNow isn't configured, or the change isn't found there) and reported
// back in the response rather than failing the whole request.
func (s *Server) handleServiceNowLinkControl(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req linkControlReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	link, status, err := s.resolveChangeControlLink(r.Context(), p.OrgID, req)
	if err != nil {
		if status >= 400 && status < 500 {
			http.Error(w, err.Error(), status)
		} else {
			internalError(w, err)
		}
		return
	}

	// Best-effort ServiceNow write-back: never fails the request.
	var sysID string
	var synced bool
	var snMessage string
	cfg, enabled, cfgErr := servicenow.NewDBLoader(s.DB, s.Secrets).ServiceNowConfig(r.Context(), p.OrgID)
	switch {
	case cfgErr != nil:
		snMessage = "failed to load ServiceNow configuration: " + cfgErr.Error()
	case !enabled:
		snMessage = "ServiceNow is not configured for this organization"
	default:
		client, err := servicenow.New(cfg)
		if err != nil {
			snMessage = "invalid ServiceNow configuration: " + err.Error()
			break
		}
		id, found, err := servicenow.WriteControlLink(r.Context(), client, req.ChangeNumber, req.ControlKey, link.ControlName, link.AttestationID.String(), link.AttestedAt)
		switch {
		case err != nil:
			snMessage = "ServiceNow write failed: " + err.Error()
		case !found:
			snMessage = "change request not found in ServiceNow: " + req.ChangeNumber
		default:
			sysID = id
			synced = true
		}
	}

	linkID, err := s.upsertChangeControlLink(r.Context(), p.OrgID, link, req.ChangeNumber, sysID, approverIdentity(p), synced)
	if err != nil {
		internalError(w, err)
		return
	}

	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		_ = events.Enqueue(r.Context(), s.q(r.Context()), p.OrgID, "servicenow.control_linked", map[string]any{
			"link_id": linkID.String(), "trail_id": link.TrailID.String(), "control": req.ControlKey,
			"change_number": req.ChangeNumber, "attestation_id": link.AttestationID.String(), "servicenow_written": synced,
		})
	}

	resp := map[string]any{
		"status":             "linked",
		"link_id":            linkID,
		"trail_id":           link.TrailID,
		"control":            req.ControlKey,
		"change_number":      req.ChangeNumber,
		"attestation_id":     link.AttestationID,
		"attested_at":        link.AttestedAt.UTC().Format(time.RFC3339),
		"servicenow_written": synced,
	}
	if sysID != "" {
		resp["servicenow_sys_id"] = sysID
	}
	if snMessage != "" {
		resp["servicenow_message"] = snMessage
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
}

// errBadRequest is a sentinel-ish helper so resolveChangeControlLink
// can return a client-facing message alongside its HTTP status without
// re-implementing error formatting at each call site.
type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }
