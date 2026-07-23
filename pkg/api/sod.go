package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"

	"fides/pkg/events"
	"fides/pkg/ledger"
)

// SegregationOfDutiesAttestationType is the well-known attestation type_name /
// name recorded on a trail proving committer, approver(s), and deployer are
// distinct identities (PCI-DSS 4.0 req 6.3 / SOX ITGC change management).
const SegregationOfDutiesAttestationType = "segregation-of-duties"

// sodAttestation is the payload recorded as the segregation-of-duties
// attestation. Shaped so ServiceNow (or any downstream consumer) can read the
// identities and roles directly off the attestation payload.
type sodAttestation struct {
	Committer  string   `json:"committer"`
	Approvers  []string `json:"approvers"`
	Deployers  []string `json:"deployers"`
	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations,omitempty"`

	// incomplete: a role identity is simply not recorded (yet). Not a
	// violation — the evidence cannot be evaluated. Unexported: never
	// serialized into the attestation payload.
	incomplete bool
	// collision: two roles share an identity — an actual SoD violation.
	collision bool
}

// identityFromTags resolves the committer identity from a trail's free-form
// tags. CI pipelines are expected to set one of these keys (e.g. via
// `fides trail start --committer <email>`) when they start a trail.
func identityFromTags(tags map[string]string) string {
	for _, key := range []string{"committer", "author", "git_author"} {
		if v := strings.TrimSpace(tags[key]); v != "" {
			return v
		}
	}
	return ""
}

// evaluateSegregationOfDuties proves committer != approver != deployer by
// checking that the committer, every recorded approver, and every recorded
// deployer are pairwise-distinct identities. Any missing identity (empty
// committer, no approver, no deployer) cannot be proven distinct and is
// therefore treated as non-compliant — the safe default for a compliance gate.
func evaluateSegregationOfDuties(committer string, approvers, deployers []string) sodAttestation {
	res := sodAttestation{
		Committer: committer,
		Approvers: approvers,
		Deployers: deployers,
		Compliant: true,
	}

	if committer == "" {
		res.Compliant = false
		res.incomplete = true
		res.Violations = append(res.Violations, "committer identity unknown")
	}
	if len(approvers) == 0 {
		res.Compliant = false
		res.incomplete = true
		res.Violations = append(res.Violations, "no approver recorded")
	}
	if len(deployers) == 0 {
		res.Compliant = false
		res.incomplete = true
		res.Violations = append(res.Violations, "no deployer recorded")
	}

	if committer != "" {
		for _, a := range approvers {
			if a == committer {
				res.Compliant = false
				res.collision = true
				res.Violations = append(res.Violations, "committer "+committer+" is also an approver")
			}
		}
		for _, d := range deployers {
			if d == committer {
				res.Compliant = false
				res.collision = true
				res.Violations = append(res.Violations, "committer "+committer+" is also the deployer")
			}
		}
	}
	for _, d := range deployers {
		for _, a := range approvers {
			if d == a {
				res.Compliant = false
				res.collision = true
				res.Violations = append(res.Violations, "deployer "+d+" is also an approver")
			}
		}
	}

	return res
}

// recordSegregationOfDutiesAttestation evaluates and records the
// segregation-of-duties attestation on a trail from its commit metadata
// (committer tag) and recorded trail_approvals (approver / deployer roles),
// chaining it into the trail's tamper-evidence ledger. Called from both the
// change-gate verdict and `fides approve` so the evidence is refreshed on
// every gate/approval action.
func (s *Server) recordSegregationOfDutiesAttestation(ctx context.Context, orgID, trailID uuid.UUID) (sodAttestation, error) {
	var tagsBytes []byte
	if err := s.q(ctx).QueryRowContext(ctx,
		`SELECT COALESCE(tags, '{}'::jsonb) FROM trails WHERE id = $1`, trailID).Scan(&tagsBytes); err != nil {
		return sodAttestation{}, err
	}
	committer := identityFromTags(unmarshalJSONB(tagsBytes))

	var approvers, deployers []string
	rows, err := s.q(ctx).QueryContext(ctx,
		`SELECT approved_by, COALESCE(NULLIF(role, ''), 'approver') FROM trail_approvals WHERE trail_id = $1 ORDER BY created_at`, trailID)
	if err != nil {
		return sodAttestation{}, err
	}
	for rows.Next() {
		var by, role string
		if err := rows.Scan(&by, &role); err != nil {
			rows.Close()
			return sodAttestation{}, err
		}
		if role == "deployer" {
			deployers = append(deployers, by)
		} else {
			approvers = append(approvers, by)
		}
	}
	rows.Close()

	result := evaluateSegregationOfDuties(committer, approvers, deployers)

	// Incomplete evidence (a role not yet recorded) is not a violation: skip
	// recording so the attestation stays MISSING — still gate-blocking — rather
	// than chaining an irreversible false verdict into the append-only ledger.
	// This evaluation runs on every approval POST, so the first (deployer)
	// approval of each deploy used to poison the trail with "no approver
	// recorded" milliseconds before the approver sign-off landed. An actual
	// identity collision is still recorded immediately.
	if result.incomplete && !result.collision {
		log.Printf("segregation-of-duties: trail %s: evidence incomplete (%v) — not recording a verdict yet", trailID, result.Violations)
		return result, nil
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return sodAttestation{}, err
	}

	// Idempotent: only chain a new attestation when the verdict actually changed.
	// The change-gate verdict is served on a GET and this also runs on every
	// approval POST, so without this guard repeated reads/no-op approvals would
	// append duplicate SoD attestations to the append-only ledger on every call
	// (#282). Compare against the trail's most recent SoD attestation payload
	// (canonicalized, since Postgres re-serializes JSONB).
	var lastPayload string
	err = s.q(ctx).QueryRowContext(ctx,
		`SELECT payload::text FROM attestations
		 WHERE trail_id = $1 AND type_name = $2
		 ORDER BY created_at DESC, id DESC LIMIT 1`, trailID, SegregationOfDutiesAttestationType).Scan(&lastPayload)
	if err != nil && err != sql.ErrNoRows {
		return sodAttestation{}, err
	}
	if err == nil && ledger.CanonicalJSON(lastPayload) == ledger.CanonicalJSON(string(payload)) {
		return result, nil // unchanged verdict — don't append a duplicate
	}

	contentHash, prevHash, err := s.attestationChain(ctx, trailID, SegregationOfDutiesAttestationType, SegregationOfDutiesAttestationType, string(payload), result.Compliant)
	if err != nil {
		return sodAttestation{}, err
	}
	if _, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO attestations (id, trail_id, name, type_name, payload, is_compliant, content_hash, prev_hash, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`,
		uuid.New(), trailID, SegregationOfDutiesAttestationType, SegregationOfDutiesAttestationType, string(payload), result.Compliant, contentHash, prevHash); err != nil {
		return sodAttestation{}, err
	}

	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && orgID != uuid.Nil {
		_ = events.Enqueue(ctx, s.q(ctx), orgID, "compliance.evaluated", map[string]any{
			"trail_id": trailID.String(), "attestation": SegregationOfDutiesAttestationType, "compliant": result.Compliant,
		})
	}

	return result, nil
}

// emitSegregationOfDutiesAttestation is a best-effort wrapper for callers
// (change-gate, approve) where the attestation is a valuable side-effect but
// must never fail the primary request the caller is servicing.
func (s *Server) emitSegregationOfDutiesAttestation(ctx context.Context, orgID, trailID uuid.UUID) *sodAttestation {
	result, err := s.recordSegregationOfDutiesAttestation(ctx, orgID, trailID)
	if err != nil {
		log.Printf("segregation-of-duties attestation: trail %s: %v", trailID, err)
		return nil
	}
	return &result
}
