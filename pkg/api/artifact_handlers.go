package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/events"
	"fides/pkg/models"
	"fides/pkg/servicenow"
)

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
	page, ok := newListPage(w, r, orgID, timeKey("a.created_at"), textKey("a.sha256"), true)
	if !ok {
		return
	}
	rows, err := s.queryPage(r, page, `
		SELECT a.sha256, a.org_id, a.trail_id, a.name, a.type, a.tags, a.created_at, COALESCE(t.name, '') /* page keys */
		FROM artifacts a
		LEFT JOIN trails t ON a.trail_id = t.id
		                  AND EXISTS (SELECT 1 FROM flows f WHERE f.id = t.flow_id AND f.org_id = $1)
		WHERE a.org_id = $1`, orgID)
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
	var digests []string
	byDigest := map[string]*ArtifactView{}
	for rows.Next() {
		var av ArtifactView
		var tagsBytes []byte
		if err := rows.Scan(&av.SHA256, &av.OrgID, &av.TrailID, &av.Name, &av.Type, &tagsBytes, &av.CreatedAt, &av.TrailName); err != nil {
			internalError(w, err)
			return
		}
		av.Tags = unmarshalJSONB(tagsBytes)
		av.SBOMStatus = "Pending"
		av.SBOM = []any{}
		list = append(list, &av)
		digests = append(digests, av.SHA256)
		byDigest[av.SHA256] = &av
	}
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	if err := rows.Close(); err != nil {
		internalError(w, err)
		return
	}

	if len(digests) == 0 {
		page.write(w, list)
		return
	}

	summaries, err := s.q(r.Context()).QueryContext(r.Context(), `
		SELECT DISTINCT ON (at.artifact_sha256) at.artifact_sha256, at.payload, at.is_compliant
		FROM attestations at
		JOIN trails tr ON tr.id = at.trail_id
		JOIN flows f ON f.id = tr.flow_id
		WHERE at.artifact_sha256 = ANY($1) AND f.org_id = $2
		  AND (at.name = 'sbom' OR at.type_name IN ('sbom', 'sbom-scan'))
		ORDER BY at.artifact_sha256, at.created_at DESC NULLS LAST, at.id DESC`, pq.Array(digests), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer summaries.Close()
	for summaries.Next() {
		var digest string
		var payload []byte
		var compliant bool
		if err := summaries.Scan(&digest, &payload, &compliant); err != nil {
			internalError(w, err)
			return
		}
		av := byDigest[digest]
		av.SBOMStatus = "Non-Compliant"
		if compliant {
			av.SBOMStatus = "Compliant"
		}
		av.SBOM = artifactSBOMPackages(payload)
	}
	if err := summaries.Err(); err != nil {
		internalError(w, err)
		return
	}
	page.write(w, list)
}

func artifactSBOMPackages(payload []byte) []any {
	var packages []any
	if err := json.Unmarshal(payload, &packages); err == nil {
		return packages
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		return []any{}
	}
	if value, ok := obj["packages"]; ok {
		packages, _ := value.([]any)
		return packages
	}
	if value, ok := obj["components"]; ok {
		packages, _ := value.([]any)
		return packages
	}
	return []any{obj}
}
