// Package modelprovenance maps EU AI Act model-provenance record-keeping onto
// Fides' existing flow/trail/artifact/attestation engine. It is intentionally
// a thin mapping layer, not a parallel engine:
//
//   - a "model" is a Flow
//   - a "model version" is a Trail on that flow (tagged with EU AI Act
//     metadata: framework, risk category, intended purpose)
//   - training/evaluation/audit evidence and inference/decision events are
//     Attestations of type AttestationType recorded on that trail
//
// Every record therefore inherits, for free, the existing per-trail
// tamper-evidence hash chain (pkg/ledger), evidence-attachment storage with
// configurable long retention (pkg/storage, FIDES_EVIDENCE_RETENTION_DAYS /
// S3 Object Lock), and search/audit-package tooling.
//
// EU AI Act anchors: Art. 12 (record-keeping / automatic logging), Art. 10
// (data & data governance for training/validation/testing sets), Art. 15
// (accuracy, robustness and cybersecurity evidence), Art. 6 (risk
// classification).
package modelprovenance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AttestationType is the fixed attestation type_name used for every
// model-provenance record, so all evidence and inference/decision events for
// every model version can be queried together (`fides search attestations
// --type model-provenance`) regardless of the specific evidence Kind.
const AttestationType = "model-provenance"

// Known evidence/event kinds recorded against a model version trail. The
// "kind" field is free text end to end (operators may record kinds we don't
// know about), but these cover the EU AI Act record-keeping obligations this
// package targets.
const (
	KindTrainingData = "training-data" // Art. 10 data & data governance
	KindEvaluation   = "evaluation"    // Art. 15 accuracy / robustness
	KindBiasAudit    = "bias-audit"    // Art. 10(2)(f) bias examination
	KindInference    = "inference-log" // Art. 12 automatic logging
	KindDecision     = "decision-log"  // Art. 12 automatic logging (human-reviewed decision)
)

// RiskCategory is the EU AI Act Art. 6 risk classification, recorded as
// model-version (trail) metadata at registration time.
type RiskCategory string

// The four EU AI Act risk tiers.
const (
	RiskUnacceptable RiskCategory = "unacceptable"
	RiskHigh         RiskCategory = "high"
	RiskLimited      RiskCategory = "limited"
	RiskMinimal      RiskCategory = "minimal"
)

// ValidRiskCategory reports whether r (case-insensitive) is one of the four
// EU AI Act risk tiers. An empty string is not valid; callers should treat
// "unset" as a separate case if the field is optional.
func ValidRiskCategory(r string) bool {
	switch RiskCategory(strings.ToLower(strings.TrimSpace(r))) {
	case RiskUnacceptable, RiskHigh, RiskLimited, RiskMinimal:
		return true
	default:
		return false
	}
}

// ModelVersion describes the model version to register as a Trail.
type ModelVersion struct {
	FlowID          string // existing Flow representing the model
	Version         string // trail name, e.g. "v1.4.0" or a training-run ID
	Repository      string // training-code repository (optional)
	Commit          string // training-code commit (optional)
	Branch          string // training-code branch (optional)
	Framework       string // e.g. "pytorch", "sklearn" (optional)
	RiskCategory    string // one of RiskUnacceptable|RiskHigh|RiskLimited|RiskMinimal (optional)
	IntendedPurpose string // Art. 13 intended purpose statement (optional)
	Tags            map[string]string
}

// TrailPayload builds the POST /api/v1/trails request body that registers a
// model version. EU AI Act metadata is folded into the trail's tag map: the
// Trail model has no bespoke columns, and tags are the existing extension
// point used elsewhere in Fides (flows/trails/artifacts are all tagged the
// same way), so this needs no schema change.
func TrailPayload(mv ModelVersion) (map[string]any, error) {
	if strings.TrimSpace(mv.FlowID) == "" {
		return nil, fmt.Errorf("modelprovenance: flow id is required")
	}
	if strings.TrimSpace(mv.Version) == "" {
		return nil, fmt.Errorf("modelprovenance: version is required")
	}
	if mv.RiskCategory != "" && !ValidRiskCategory(mv.RiskCategory) {
		return nil, fmt.Errorf("modelprovenance: invalid risk category %q (want one of unacceptable|high|limited|minimal)", mv.RiskCategory)
	}

	tags := make(map[string]string, len(mv.Tags)+4)
	for k, v := range mv.Tags {
		tags[k] = v
	}
	// Marks this trail as a model version so `fides model versions` and any
	// future UI can find it without depending on tag ordering.
	tags["model_provenance"] = "true"
	if mv.Framework != "" {
		tags["framework"] = mv.Framework
	}
	if mv.RiskCategory != "" {
		tags["risk_category"] = strings.ToLower(mv.RiskCategory)
	}
	if mv.IntendedPurpose != "" {
		tags["intended_purpose"] = mv.IntendedPurpose
	}

	return map[string]any{
		"flow_id":        mv.FlowID,
		"name":           mv.Version,
		"git_repository": mv.Repository,
		"git_commit":     mv.Commit,
		"git_branch":     mv.Branch,
		"git_message":    "",
		"tags":           tags,
	}, nil
}

// Evidence is training/evaluation/audit evidence recorded against a model
// version (Art. 10/15).
type Evidence struct {
	Kind      string // e.g. KindTrainingData, KindEvaluation, KindBiasAudit
	Compliant bool
	Summary   map[string]any // e.g. dataset size, metric scores
	Findings  []string
	Metadata  map[string]any
}

// EvidencePayload marshals ev into the normalized JSON string recorded as an
// attestation payload. The envelope is deliberately jq-evaluable (like
// pkg/evidence.Result) so operators can attach environment policies that
// require `.compliant == true` on model-provenance evidence.
func EvidencePayload(ev Evidence) (string, error) {
	if strings.TrimSpace(ev.Kind) == "" {
		return "", fmt.Errorf("modelprovenance: evidence kind is required")
	}
	doc := map[string]any{
		"kind":        ev.Kind,
		"compliant":   ev.Compliant,
		"summary":     ev.Summary,
		"findings":    ev.Findings,
		"metadata":    ev.Metadata,
		"recorded_at": time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("modelprovenance: marshal evidence: %w", err)
	}
	return string(b), nil
}

// InferenceEvent is a single inference/decision record. Art. 12 requires
// automatic logging of, at minimum, the period of use, the reference
// database queried, the input data for which the search led to a match, and
// the identification of the natural persons involved in verifying results;
// this package hashes inputs/outputs by design (the CLI never uploads raw
// input data) so the log itself does not become a second copy of personal
// data.
type InferenceEvent struct {
	InputHash  string // sha256 of the input; never the raw input
	OutputHash string // sha256 of the output/result, if applicable
	Decision   string // the decision or result produced
	Confidence *float64
	Actor      string // human reviewer, if any (Art. 14 human oversight)
	Metadata   map[string]any
	Timestamp  time.Time
}

// InferenceLogPayload marshals ev into the JSON attestation payload for an
// inference/decision-log record.
func InferenceLogPayload(ev InferenceEvent) (string, error) {
	if strings.TrimSpace(ev.InputHash) == "" {
		return "", fmt.Errorf("modelprovenance: input hash is required")
	}
	if strings.TrimSpace(ev.Decision) == "" {
		return "", fmt.Errorf("modelprovenance: decision is required")
	}
	if ev.Confidence != nil && (*ev.Confidence < 0 || *ev.Confidence > 1) {
		return "", fmt.Errorf("modelprovenance: confidence must be between 0 and 1")
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	doc := map[string]any{
		"input_hash":  ev.InputHash,
		"output_hash": ev.OutputHash,
		"decision":    ev.Decision,
		"confidence":  ev.Confidence,
		"actor":       ev.Actor,
		"metadata":    ev.Metadata,
		"logged_at":   ts.UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("modelprovenance: marshal inference event: %w", err)
	}
	return string(b), nil
}
