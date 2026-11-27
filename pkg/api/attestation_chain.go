package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/google/uuid"

	"fides/pkg/db"
	"fides/pkg/events"
	"fides/pkg/ledger"
	"fides/pkg/models"
)

// appendAttestation serializes chain appends for a trail. Ordinary ingestion
// supplies ingestOrg to store its signing fields and optionally enqueue its event.
func (s *Server) appendAttestation(ctx context.Context, att *models.Attestation, ingestOrg *uuid.UUID) error {
	if q, ok := db.QuerierFromContext(ctx); ok {
		if tx, ok := q.(*sql.Tx); ok {
			return insertAttestation(ctx, tx, att, ingestOrg)
		}
	}
	tx, err := db.BeginTx(ctx, s.DB, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAttestation(ctx, tx, att, ingestOrg); err != nil {
		return err
	}
	return tx.Commit()
}

func insertAttestation(ctx context.Context, tx *sql.Tx, att *models.Attestation, ingestOrg *uuid.UUID) error {
	if att.ValidationErrors == nil {
		att.ValidationErrors = []models.AttestationValidationError{}
	}
	reasons, err := json.Marshal(att.ValidationErrors)
	if err != nil {
		return err
	}
	canonical := ledger.CanonicalJSON(att.Payload)

	// Read the head in a separate statement so it sees the last lock holder's commit.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('attestation-chain:' || $1::text, 0))`, att.TrailID.String()); err != nil {
		return err
	}
	var prevHash string
	var prevTime sql.NullTime
	err = tx.QueryRowContext(ctx,
		`SELECT content_hash, created_at FROM attestations
		 WHERE trail_id = $1 AND content_hash IS NOT NULL
		 ORDER BY created_at DESC, id DESC LIMIT 1`, att.TrailID).Scan(&prevHash, &prevTime)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	contentHash := ledger.ContentHash(att.TrailID.String(), att.Name, att.TypeName, canonical, att.IsCompliant, prevHash)
	ordinary := ingestOrg != nil
	err = tx.QueryRowContext(ctx,
		`INSERT INTO attestations (id, trail_id, artifact_sha256, name, type_name, payload, is_compliant,
		 signed_by, signature, signature_algorithm, manifestation_reason, content_hash, prev_hash, created_at, validation_errors)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		 CASE WHEN $8 THEN $9::varchar END, CASE WHEN $8 THEN $10::text END,
		 CASE WHEN $8 THEN $11::varchar END, CASE WHEN $8 THEN $12::text END, $13, $14,
		 GREATEST(clock_timestamp(), $15::timestamptz + interval '1 microsecond'), $16)
		 RETURNING created_at`,
		att.ID, att.TrailID, att.ArtifactSHA256, att.Name, att.TypeName, att.Payload, att.IsCompliant,
		ordinary, att.SignedBy, att.Signature, att.SignatureAlgorithm, att.ManifestationReason, contentHash, prevHash, prevTime, string(reasons)).
		Scan(&att.CreatedAt)
	if err != nil {
		return err
	}

	if ordinary && os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if err := events.Enqueue(ctx, tx, *ingestOrg, "compliance.evaluated", map[string]any{
			"trail_id": att.TrailID.String(),
			// Status messages use the display name. Control matching uses the type.
			"attestation":      att.Name,
			"attestation_type": att.TypeName,
			"compliant":        att.IsCompliant,
		}); err != nil {
			return err
		}
	}
	return nil
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
	if !s.requireTrailInOrg(w, r, trailID) {
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
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
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
