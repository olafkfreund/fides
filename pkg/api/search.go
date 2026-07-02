package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
)

// handleSearchArtifacts filters artifacts by SHA prefix, git commit, or name.
func (s *Server) handleSearchArtifacts(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sha := r.URL.Query().Get("sha")
	commit := r.URL.Query().Get("commit")
	name := r.URL.Query().Get("name")

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT a.sha256, a.name, a.type, a.created_at, COALESCE(t.git_commit, '')
		 FROM artifacts a LEFT JOIN trails t ON t.id = a.trail_id
		 WHERE a.org_id = $1
		   AND ($2 = '' OR a.sha256 LIKE $2 || '%')
		   AND ($3 = '' OR t.git_commit = $3)
		   AND ($4 = '' OR a.name ILIKE '%' || $4 || '%')
		 ORDER BY a.created_at DESC LIMIT 100`, orgID, sha, commit, name)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var sha256, n, typ, gitCommit string
		var created interface{}
		if err := rows.Scan(&sha256, &n, &typ, &created, &gitCommit); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"sha256": sha256, "name": n, "type": typ, "git_commit": gitCommit, "created_at": created})
	}
	writeJSON(w, out)
}

// handleSearchAttestations filters attestations by type, trail, or compliance.
func (s *Server) handleSearchAttestations(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	typeName := r.URL.Query().Get("type")
	compliant := r.URL.Query().Get("compliant") // "", "true", "false"
	sha := r.URL.Query().Get("sha")             // filter to one artifact's attestations
	trail := ""
	if t := r.URL.Query().Get("trail"); t != "" {
		if _, err := uuid.Parse(t); err != nil {
			http.Error(w, "trail must be a UUID", http.StatusBadRequest)
			return
		}
		trail = t
	}

	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT at.id, at.name, at.type_name, at.is_compliant, at.created_at, at.trail_id
		 FROM attestations at JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1
		   AND ($2 = '' OR at.type_name = $2)
		   AND ($3 = '' OR at.trail_id = NULLIF($3, '')::uuid)
		   AND ($4 = '' OR at.is_compliant = ($4 = 'true'))
		   AND ($5 = '' OR at.artifact_sha256 = $5)
		 ORDER BY at.created_at DESC LIMIT 100`, orgID, typeName, trail, compliant, sha)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, trailID uuid.UUID
		var name, typ string
		var isCompliant bool
		var created interface{}
		if err := rows.Scan(&id, &name, &typ, &isCompliant, &created, &trailID); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "type_name": typ, "is_compliant": isCompliant, "trail_id": trailID, "created_at": created})
	}
	writeJSON(w, out)
}

// handleGetAttestation returns a single attestation with its full evidence
// payload and signing/tamper-evidence metadata (tenant-scoped). Powers the
// artifact/attestation detail views. The payload is JSONB, returned verbatim.
func (s *Server) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid attestation id", http.StatusBadRequest)
		return
	}
	var (
		name, typeName, signedBy, sigAlgo, manifest, contentHash, artSha string
		isCompliant                                                      bool
		payload                                                          []byte
		created                                                          interface{}
		trailID                                                          uuid.UUID
	)
	err = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT at.name, at.type_name, at.is_compliant, at.payload,
		        COALESCE(at.signed_by,''), COALESCE(at.signature_algorithm,''),
		        COALESCE(at.manifestation_reason,''), COALESCE(at.content_hash,''),
		        at.created_at, at.trail_id, COALESCE(at.artifact_sha256,'')
		 FROM attestations at JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE at.id = $1 AND f.org_id = $2`, id, orgID).
		Scan(&name, &typeName, &isCompliant, &payload, &signedBy, &sigAlgo, &manifest, &contentHash, &created, &trailID, &artSha)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "attestation not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	// payload is valid JSONB; embed verbatim (fall back to a JSON string if empty).
	raw := json.RawMessage(payload)
	if len(payload) == 0 {
		raw = json.RawMessage(`null`)
	}
	writeJSON(w, map[string]any{
		"id": id, "name": name, "type_name": typeName, "is_compliant": isCompliant,
		"payload": raw, "signed_by": signedBy, "signature_algorithm": sigAlgo,
		"manifestation_reason": manifest, "content_hash": contentHash,
		"created_at": created, "trail_id": trailID, "artifact_sha256": artSha,
	})
}

// handleSnapshotDiff compares the running services of two snapshots of an
// environment (defaulting to the two most recent), reporting added/removed/changed.
func (s *Server) handleSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	owned, err := s.envInOrg(r.Context(), envID, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !owned {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}

	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	diff, err := s.diffSnapshots(r.Context(), envID, from, to)
	if err != nil {
		if errors.Is(err, errNeedTwoSnapshots) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		internalError(w, err)
		return
	}
	writeJSON(w, diff)
}

// errNeedTwoSnapshots is returned by diffSnapshots when an environment has
// fewer than two snapshots and no explicit from/to was given.
var errNeedTwoSnapshots = errors.New("need at least two snapshots to diff")

// diffSnapshots computes the added/removed/changed services between two
// snapshots of an environment (defaulting to the two most recent). Shared by
// the HTTP diff endpoint and the post-approval drift re-evaluation path.
func (s *Server) diffSnapshots(ctx context.Context, envID uuid.UUID, from, to string) (map[string]any, error) {
	if from == "" || to == "" {
		// Default to the two most recent snapshots.
		ids, err := s.recentSnapshotIDs(ctx, envID)
		if err != nil {
			return nil, err
		}
		if len(ids) < 2 {
			return nil, errNeedTwoSnapshots
		}
		to, from = ids[0], ids[1] // ids[0] is newest
	}

	fromMap, err := s.snapshotServices(ctx, from)
	if err != nil {
		return nil, err
	}
	toMap, err := s.snapshotServices(ctx, to)
	if err != nil {
		return nil, err
	}

	added, removed := []map[string]string{}, []map[string]string{}
	changed := []map[string]string{}
	for svc, dig := range toMap {
		if old, ok := fromMap[svc]; !ok {
			added = append(added, map[string]string{"service": svc, "digest": dig})
		} else if old != dig {
			changed = append(changed, map[string]string{"service": svc, "from": old, "to": dig})
		}
	}
	for svc, dig := range fromMap {
		if _, ok := toMap[svc]; !ok {
			removed = append(removed, map[string]string{"service": svc, "digest": dig})
		}
	}
	return map[string]any{"from": from, "to": to, "added": added, "removed": removed, "changed": changed}, nil
}

func (s *Server) recentSnapshotIDs(ctx context.Context, envID uuid.UUID) ([]string, error) {
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT id FROM environment_snapshots WHERE environment_id = $1 ORDER BY created_at DESC LIMIT 2`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Server) snapshotServices(ctx context.Context, snapshotID string) (map[string]string, error) {
	sid, err := uuid.Parse(snapshotID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT service_name, runtime_digest FROM snapshot_artifacts WHERE snapshot_id = $1`, sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var svc, dig string
		if err := rows.Scan(&svc, &dig); err != nil {
			return nil, err
		}
		m[svc] = dig
	}
	return m, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
