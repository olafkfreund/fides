package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
)

// provenanceStatement is the subset of an in-toto statement fields for SLSA
// provenance, supporting both the SLSA v1.0 shape
// (predicate.buildDefinition.buildType / predicate.runDetails.builder.id) and
// the legacy SLSA v0.2 shape (predicate.buildType / predicate.builder.id).
type provenanceStatement struct {
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildType       string `json:"buildType"` // SLSA v0.2
		BuildDefinition struct {
			BuildType string `json:"buildType"` // SLSA v1.0
		} `json:"buildDefinition"`
		Builder struct {
			ID string `json:"id"` // SLSA v0.2
		} `json:"builder"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"` // SLSA v1.0
			} `json:"builder"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

// NormalizeProvenance decodes a raw in-toto/SLSA provenance statement (as
// fetched from a git provider's native attestation store, e.g.
// pkg/gitstatus.FetchAttestations) into a Result. When expectedSHA256 is
// non-empty, the statement is only compliant if one of its subjects' sha256
// digest matches it, so a fetched attestation can't be silently attached to
// the wrong artifact.
func NormalizeProvenance(statement []byte, expectedSHA256 string) (Result, error) {
	var st provenanceStatement
	if err := json.Unmarshal(statement, &st); err != nil {
		return Result{}, fmt.Errorf("evidence: parse provenance statement: %w", err)
	}
	if st.PredicateType == "" {
		return Result{}, fmt.Errorf("evidence: provenance statement missing predicateType")
	}

	builderID := st.Predicate.RunDetails.Builder.ID
	if builderID == "" {
		builderID = st.Predicate.Builder.ID
	}
	buildType := st.Predicate.BuildDefinition.BuildType
	if buildType == "" {
		buildType = st.Predicate.BuildType
	}

	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	digestMatch := expected == ""
	if !digestMatch {
		for _, s := range st.Subject {
			if strings.EqualFold(s.Digest["sha256"], expected) {
				digestMatch = true
				break
			}
		}
	}

	var findings []string
	if expected != "" && !digestMatch {
		findings = append(findings, fmt.Sprintf("no subject digest matches expected artifact sha256 %s", expected))
	}
	if builderID == "" {
		findings = append(findings, "provenance statement is missing runDetails.builder.id / builder.id")
	}

	return Result{
		Format:    "provenance",
		Compliant: digestMatch && builderID != "",
		Summary: map[string]any{
			"predicate_type": st.PredicateType,
			"build_type":     buildType,
			"builder_id":     builderID,
			"subject_count":  len(st.Subject),
			"digest_match":   digestMatch,
		},
		Findings: findings,
	}, nil
}
