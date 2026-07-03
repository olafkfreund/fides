package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
	"fides/pkg/servicenow"
)

type deploymentAnchorReq struct {
	TrailID      string `json:"trail_id"`
	ChangeNumber string `json:"change_number,omitempty"` // preferred: resolves the CI via change_request.cmdb_ci
	CI           string `json:"ci,omitempty"`            // CMDB CI name (alternative/fallback to change_number)
	BuildLogRef  string `json:"build_log_ref,omitempty"` // pointer to the build log (CI run URL, etc.)
}

// handleServiceNowAnchorDeployment attaches a signed deployment attestation
// (image digest, commit, build log ref, runtime snapshot ref) to the relevant
// ServiceNow CMDB CI. Called on change close / deploy, it proves the deployed
// artifact matched change intent: it resolves the CI via the change request's
// cmdb_ci reference (preferred, since that's what the change actually
// authorized) or an explicit CI name, records the anchor as Fides-side
// evidence (independent of ServiceNow reachability), and — when the event
// pipeline is enabled — enqueues delivery to ServiceNow via the CMDB sink
// (durable, at-least-once; see pkg/servicenow.AnchorDeploymentAttestation).
func (s *Server) handleServiceNowAnchorDeployment(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req deploymentAnchorReq
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

	client, enabled, err := s.snowClient(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !enabled {
		http.Error(w, "ServiceNow is not configured for this organization", http.StatusBadRequest)
		return
	}

	ciSysID, ciName, err := s.resolveDeploymentCI(r.Context(), client, req.ChangeNumber, req.CI)
	if err != nil {
		internalError(w, err)
		return
	}
	if ciSysID == "" {
		http.Error(w, "could not resolve a CMDB CI from change_number/ci", http.StatusNotFound)
		return
	}

	var flowName, commit string
	err = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT f.name, COALESCE(t.git_commit, '') FROM trails t
		 JOIN flows f ON f.id = t.flow_id
		 WHERE t.id = $1 AND f.org_id = $2`, trailID, orgID).Scan(&flowName, &commit)
	if err == sql.ErrNoRows {
		http.Error(w, "trail not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	// Latest attestation on the trail that carries an artifact fingerprint is
	// taken as "what was deployed" (image digest); its content_hash ties the
	// anchor back into the trail's tamper-evidence chain (see pkg/ledger).
	var digest, attestationID, contentHash string
	var compliant bool
	err = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT COALESCE(a.artifact_sha256, ''), a.id::text, COALESCE(a.content_hash, ''), a.is_compliant
		 FROM attestations a WHERE a.trail_id = $1 AND a.artifact_sha256 IS NOT NULL
		 ORDER BY a.created_at DESC LIMIT 1`, trailID).Scan(&digest, &attestationID, &contentHash, &compliant)
	if err != nil && err != sql.ErrNoRows {
		internalError(w, err)
		return
	}

	// Best-effort: the most recent runtime snapshot of this trail's artifact
	// proves it's actually running, not just built.
	var snapshotRef string
	_ = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT sa.snapshot_id::text FROM snapshot_artifacts sa
		 JOIN artifacts art ON art.sha256 = sa.artifact_sha256
		 WHERE art.trail_id = $1 ORDER BY sa.started_at DESC NULLS LAST LIMIT 1`, trailID).Scan(&snapshotRef)

	att := servicenow.DeploymentAttestation{
		CI: ciName, CISysID: ciSysID, ChangeNumber: req.ChangeNumber,
		TrailID: trailID.String(), FlowName: flowName,
		ImageDigest: digest, Commit: commit, BuildLogRef: req.BuildLogRef,
		SnapshotRef: snapshotRef, AttestationID: attestationID, ContentHash: contentHash,
		Compliant: compliant, AnchoredAt: time.Now().UTC(),
	}

	anchorID := uuid.New()
	_, err = s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO deployment_anchors
		 (id, org_id, trail_id, attestation_id, ci_sys_id, ci_name, change_number, image_digest, commit_sha, build_log_ref, runtime_snapshot_ref, content_hash, compliant, created_at)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())`,
		anchorID, orgID, trailID, attestationID, ciSysID, ciName, req.ChangeNumber, digest, commit, req.BuildLogRef, snapshotRef, contentHash, compliant)
	if err != nil {
		internalError(w, err)
		return
	}

	queued := false
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, servicenow.AnchorEventType, att); err != nil {
			internalError(w, err)
			return
		}
		queued = true
	}

	writeJSON(w, map[string]any{
		"anchor_id":     anchorID,
		"ci_sys_id":     ciSysID,
		"ci_name":       ciName,
		"change_number": req.ChangeNumber,
		"queued":        queued,
	})
}

// resolveDeploymentCI resolves a CMDB CI sys_id (and name), preferring the
// change request's cmdb_ci reference — what the change actually authorized —
// and falling back to a direct name search when no change number is given or
// the change has no CI linked.
func (s *Server) resolveDeploymentCI(ctx context.Context, client *servicenow.Client, changeNumber, ci string) (sysID, name string, err error) {
	if changeNumber != "" {
		cr, found, err := servicenow.QueryChangeRequest(ctx, client, "number="+changeNumber)
		if err != nil {
			return "", "", err
		}
		if found {
			sysID = referenceSysID(cr["cmdb_ci"])
		}
	}
	if sysID == "" && ci != "" {
		res, err := client.QueryTable(ctx, "cmdb_ci", "nameLIKE"+ci+"^active=true", "sys_id", "name")
		if err != nil {
			return "", "", err
		}
		if len(res.Result) > 0 {
			sysID, _ = res.Result[0]["sys_id"].(string)
			name, _ = res.Result[0]["name"].(string)
		}
	}
	if name == "" {
		name = ci
	}
	return sysID, name, nil
}

// referenceSysID extracts a sys_id from a ServiceNow reference-field value,
// which the Table API returns either as a bare string or as
// {"value": "<sys_id>", "link": "..."} depending on sysparm_display_value.
func referenceSysID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		s, _ := t["value"].(string)
		return s
	default:
		return ""
	}
}

// handleListDeploymentAnchors lists the deployment-to-CI anchors recorded for
// a trail — Fides-side evidence of anchoring, independent of ServiceNow
// reachability at read time.
func (s *Server) handleListDeploymentAnchors(w http.ResponseWriter, r *http.Request) {
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
		`SELECT id, ci_sys_id, COALESCE(ci_name, ''), COALESCE(change_number, ''), COALESCE(image_digest, ''),
		        COALESCE(commit_sha, ''), COALESCE(build_log_ref, ''), COALESCE(runtime_snapshot_ref, ''), compliant, created_at
		 FROM deployment_anchors WHERE trail_id = $1 AND org_id = $2 ORDER BY created_at DESC`, trailID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var ciSysID, ciName, changeNumber, digest, commit, buildLog, snapshotRef string
		var compliant bool
		var created time.Time
		if err := rows.Scan(&id, &ciSysID, &ciName, &changeNumber, &digest, &commit, &buildLog, &snapshotRef, &compliant, &created); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{
			"id": id, "ci_sys_id": ciSysID, "ci_name": ciName, "change_number": changeNumber,
			"image_digest": digest, "commit": commit, "build_log_ref": buildLog,
			"runtime_snapshot_ref": snapshotRef, "compliant": compliant, "created_at": created,
		})
	}
	writeJSON(w, out)
}
