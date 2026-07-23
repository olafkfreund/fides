package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"fides/pkg/ledger"
)

// attestationChain computes the content_hash and prev_hash for a new attestation
// being added to a trail (the append-only tamper-evidence chain). prev_hash is
// the content_hash of the trail's most recent chained attestation.
func (s *Server) attestationChain(ctx context.Context, trailID uuid.UUID, name, typeName, payload string, isCompliant bool) (contentHash, prevHash string, err error) {
	err = s.q(ctx).QueryRowContext(ctx,
		`SELECT COALESCE(content_hash, '') FROM attestations
		 WHERE trail_id = $1 AND content_hash IS NOT NULL
		 ORDER BY created_at DESC, id DESC LIMIT 1`, trailID).Scan(&prevHash)
	if err == sql.ErrNoRows {
		prevHash, err = "", nil
	}
	if err != nil {
		return "", "", err
	}
	canonical := ledger.CanonicalJSON(payload)
	return ledger.ContentHash(trailID.String(), name, typeName, canonical, isCompliant, prevHash), prevHash, nil
}

// handleVerifyTrailChain verifies a trail's attestation hash chain, detecting any
// tampering, deletion, or reordering.
func (s *Server) handleVerifyTrailChain(w http.ResponseWriter, r *http.Request) {
	if _, ok := principalOrg(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT name, type_name, payload::text, is_compliant, COALESCE(content_hash, ''), COALESCE(prev_hash, '')
		 FROM attestations WHERE trail_id = $1 ORDER BY created_at, id`, trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	var entries []ledger.Entry
	for rows.Next() {
		var e ledger.Entry
		var payload string
		if err := rows.Scan(&e.Name, &e.TypeName, &payload, &e.IsCompliant, &e.ContentHash, &e.PrevHash); err != nil {
			internalError(w, err)
			return
		}
		e.TrailID = trailID.String()
		e.Payload = ledger.CanonicalJSON(payload)
		entries = append(entries, e)
	}

	verdict := ledger.Verify(entries)

	// The current chain head is the last entry's content_hash; compare it against
	// any external RFC3161 anchor to prove the head existed at a point in time.
	head := ""
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].ContentHash != "" {
			head = entries[i].ContentHash
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chainVerifyResp{
		Verdict:        verdict,
		ExternalAnchor: s.externalAnchorStatus(r.Context(), trailID, head),
	})
}
