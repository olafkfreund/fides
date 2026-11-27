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

type attachmentCommitment struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Hash string    `json:"sha256"`
}

type attestationEvidence struct {
	ArtifactSHA256      *string                `json:"artifact_sha256"`
	SignedBy            *string                `json:"signed_by"`
	Signature           *string                `json:"signature"`
	SignatureAlgorithm  *string                `json:"signature_algorithm"`
	ManifestationReason *string                `json:"manifestation_reason"`
	Policy              *attestationPolicy     `json:"policy"`
	Attachments         []attachmentCommitment `json:"attachments"`
}

// appendAttestation serializes chain appends for a trail. Ordinary ingestion
// supplies ingestOrg to store its signing fields and optionally enqueue its event.
func (s *Server) appendAttestation(ctx context.Context, att *models.Attestation, ingestOrg *uuid.UUID, inputs attestationEvidence) error {
	if q, ok := db.QuerierFromContext(ctx); ok {
		if tx, ok := q.(*sql.Tx); ok {
			return insertAttestation(ctx, tx, att, ingestOrg, inputs)
		}
	}
	tx, err := db.BeginTx(ctx, s.DB, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAttestation(ctx, tx, att, ingestOrg, inputs); err != nil {
		return err
	}
	return tx.Commit()
}

func insertAttestation(ctx context.Context, tx *sql.Tx, att *models.Attestation, ingestOrg *uuid.UUID, inputs attestationEvidence) error {
	if att.ValidationErrors == nil {
		att.ValidationErrors = []models.AttestationValidationError{}
	}
	reasons, err := json.Marshal(att.ValidationErrors)
	if err != nil {
		return err
	}
	inputs.ArtifactSHA256 = att.ArtifactSHA256
	if ingestOrg != nil {
		inputs.SignedBy = &att.SignedBy
		inputs.Signature = &att.Signature
		inputs.SignatureAlgorithm = &att.SignatureAlgorithm
		inputs.ManifestationReason = &att.ManifestationReason
	}
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

	version := 1
	var evidence any
	contentHash := ledger.ContentHash(att.TrailID.String(), att.Name, att.TypeName,
		ledger.CanonicalJSON(att.Payload), att.IsCompliant, prevHash)
	// Enable new writes once every active ledger reader supports version 2.
	if os.Getenv("FIDES_LEDGER_EVIDENCE_V2") == "true" {
		if inputs.Attachments == nil {
			inputs.Attachments = []attachmentCommitment{}
		}
		rawEvidence, err := json.Marshal(inputs)
		if err != nil {
			return err
		}
		canonical := ledger.CanonicalJSONV2(string(rawEvidence))
		contentHash = ledger.ContentHashV2(att.TrailID.String(), att.Name, att.TypeName, att.Payload, att.IsCompliant, prevHash, canonical)
		if contentHash == "" {
			return errors.New("could not hash attestation evidence inputs")
		}
		version, evidence = 2, canonical
	}
	err = tx.QueryRowContext(ctx,
		`INSERT INTO attestations (id, trail_id, artifact_sha256, name, type_name, payload, is_compliant,
		 signed_by, signature, signature_algorithm, manifestation_reason, content_hash, prev_hash, created_at,
		 validation_errors, hash_version, evidence_inputs)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		 GREATEST(clock_timestamp(), $14::timestamptz + interval '1 microsecond'), $15, $16, $17)
		 RETURNING created_at`,
		att.ID, att.TrailID, att.ArtifactSHA256, att.Name, att.TypeName, att.Payload, att.IsCompliant,
		inputs.SignedBy, inputs.Signature, inputs.SignatureAlgorithm, inputs.ManifestationReason,
		contentHash, prevHash, prevTime, string(reasons), version, evidence).
		Scan(&att.CreatedAt)
	if err != nil {
		return err
	}

	if ingestOrg != nil && os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
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

type trailChainEntry struct {
	ledger.Entry
	id              string
	rawPayload      string
	artifactSHA256  *string
	createdAt       sql.NullTime
	evidenceMatches bool
}

// Read attachment and attestation metadata from the same database snapshot.
// The policy definition is historical and verified by the hash itself.
func (s *Server) readTrailChain(ctx context.Context, trailID uuid.UUID) ([]trailChainEntry, error) {
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT a.id, a.name, a.type_name, a.payload::text, a.is_compliant,
		        COALESCE(a.content_hash, ''), COALESCE(a.prev_hash, ''), a.created_at,
		        a.hash_version, COALESCE(a.evidence_inputs::text, ''), a.artifact_sha256,
		        CASE WHEN a.hash_version = 2 THEN COALESCE(a.evidence_inputs = jsonb_build_object(
		            'artifact_sha256', a.artifact_sha256, 'signed_by', a.signed_by, 'signature', a.signature,
		            'signature_algorithm', a.signature_algorithm, 'manifestation_reason', a.manifestation_reason,
		            'policy', a.evidence_inputs -> 'policy',
		            'attachments', COALESCE((
		                SELECT jsonb_agg(jsonb_build_object('id', e.id, 'name', e.file_name, 'size', e.file_size,
		                                                 'sha256', e.file_hash) ORDER BY e.id)
		                FROM evidence_attachments e WHERE e.attestation_id = a.id
		            ), '[]'::jsonb)
		        ), false) ELSE a.evidence_inputs IS NULL END
		 FROM attestations a WHERE a.trail_id = $1 ORDER BY a.created_at, a.id`, trailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []trailChainEntry
	for rows.Next() {
		e := trailChainEntry{Entry: ledger.Entry{TrailID: trailID.String()}}
		if err := rows.Scan(&e.id, &e.Name, &e.TypeName, &e.rawPayload, &e.IsCompliant, &e.ContentHash, &e.PrevHash,
			&e.createdAt, &e.Version, &e.Evidence, &e.artifactSHA256, &e.evidenceMatches); err != nil {
			return nil, err
		}
		e.Payload = e.rawPayload
		if e.Version == 2 {
			e.Evidence = ledger.CanonicalJSONV2(e.Evidence)
		} else {
			e.Payload = ledger.CanonicalJSON(e.rawPayload)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func verifyTrailEntries(entries []trailChainEntry) ledger.Verdict {
	chain := make([]ledger.Entry, 0, len(entries))
	for _, entry := range entries {
		if !entry.evidenceMatches {
			break
		}
		chain = append(chain, entry.Entry)
	}
	verdict := ledger.Verify(chain)
	if verdict.Valid && len(chain) < len(entries) {
		verdict.Valid = false
		verdict.BrokenAt = len(chain)
		verdict.Reason = "evidence inputs do not match stored attestation and attachments"
	}
	if !verdict.Valid {
		verdict.Count = len(entries)
	}
	return verdict
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
	entries, err := s.readTrailChain(r.Context(), trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	verdict := verifyTrailEntries(entries)

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
