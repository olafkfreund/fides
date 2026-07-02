package api

import (
	"context"

	"github.com/google/uuid"

	"fides/pkg/ledger"
)

// computeEvidenceBundle assembles the tamper-evident evidence summary for a
// trail: the attestation hash-chain verdict (detects deletion/reorder/
// tampering), the artifact digests produced by the trail, and a per-type
// attestation compliance count. This is the "signed evidence bundle" attached
// alongside the risk score on the ServiceNow change-gate write-back, so the
// change_request carries more than a verdict — it carries the evidence.
func (s *Server) computeEvidenceBundle(ctx context.Context, trailID uuid.UUID) (map[string]any, error) {
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT name, type_name, payload::text, is_compliant, COALESCE(content_hash,''), COALESCE(prev_hash,'')
		 FROM attestations WHERE trail_id = $1 ORDER BY created_at, id`, trailID)
	if err != nil {
		return nil, err
	}
	var entries []ledger.Entry
	typeCounts := map[string]map[string]int{}
	for rows.Next() {
		var e ledger.Entry
		var payload string
		if err := rows.Scan(&e.Name, &e.TypeName, &payload, &e.IsCompliant, &e.ContentHash, &e.PrevHash); err != nil {
			rows.Close()
			return nil, err
		}
		e.TrailID = trailID.String()
		e.Payload = ledger.CanonicalJSON(payload)
		entries = append(entries, e)

		tc, ok := typeCounts[e.TypeName]
		if !ok {
			tc = map[string]int{"total": 0, "compliant": 0, "non_compliant": 0}
			typeCounts[e.TypeName] = tc
		}
		tc["total"]++
		if e.IsCompliant {
			tc["compliant"]++
		} else {
			tc["non_compliant"]++
		}
	}
	rows.Close()

	artifacts := []map[string]any{}
	arows, err := s.q(ctx).QueryContext(ctx,
		`SELECT sha256, name, type FROM artifacts WHERE trail_id = $1 ORDER BY created_at`, trailID)
	if err != nil {
		return nil, err
	}
	for arows.Next() {
		var sha, name, typ string
		if err := arows.Scan(&sha, &name, &typ); err != nil {
			arows.Close()
			return nil, err
		}
		artifacts = append(artifacts, map[string]any{"sha256": sha, "name": name, "type": typ})
	}
	arows.Close()

	return map[string]any{
		"chain":             ledger.Verify(entries),
		"artifacts":         artifacts,
		"attestation_types": typeCounts,
	}, nil
}
