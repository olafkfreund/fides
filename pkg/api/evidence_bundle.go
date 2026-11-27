package api

import (
	"context"

	"github.com/google/uuid"
)

// computeEvidenceBundle assembles the tamper-evident evidence summary for a
// trail: the attestation hash-chain verdict (detects deletion/reorder/
// tampering), the artifact digests produced by the trail, and a per-type
// attestation compliance count. This is the "signed evidence bundle" attached
// alongside the risk score on the ServiceNow change-gate write-back, so the
// change_request carries more than a verdict — it carries the evidence.
func (s *Server) computeEvidenceBundle(ctx context.Context, trailID uuid.UUID) (map[string]any, error) {
	entries, err := s.readTrailChain(ctx, trailID)
	if err != nil {
		return nil, err
	}
	typeCounts := map[string]map[string]int{}
	for _, e := range entries {
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
	artifacts := []map[string]any{}
	arows, err := s.q(ctx).QueryContext(ctx,
		`SELECT sha256, name, type FROM artifacts WHERE trail_id = $1 ORDER BY created_at`, trailID)
	if err != nil {
		return nil, err
	}
	defer arows.Close()
	for arows.Next() {
		var sha, name, typ string
		if err := arows.Scan(&sha, &name, &typ); err != nil {
			arows.Close()
			return nil, err
		}
		artifacts = append(artifacts, map[string]any{"sha256": sha, "name": name, "type": typ})
	}
	// A failed iteration must not read as a short result.
	if err := arows.Err(); err != nil {
		arows.Close()
		return nil, err
	}
	arows.Close()

	return map[string]any{
		"chain":             verifyTrailEntries(entries),
		"artifacts":         artifacts,
		"attestation_types": typeCounts,
	}, nil
}
