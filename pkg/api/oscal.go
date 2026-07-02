package api

import (
	"time"

	"github.com/google/uuid"
)

// OSCAL assessment-results structs.
//
// This is a minimal, valid subset of the NIST OSCAL 1.x assessment-results
// model (https://pages.nist.gov/OSCAL/resources/1.1/json-outline/assessment-results/)
// — enough to carry Fides' control -> collected-evidence mapping for a
// framework in the shape FedRAMP 20x and other OSCAL consumers expect:
// metadata, a single result with reviewed-controls, findings (one per
// control, with a satisfied/not-satisfied status), and observations (the
// collected evidence backing each finding).
//
// We intentionally keep this a hand-rolled subset rather than a full schema
// implementation: Fides' evidence model (attestation types satisfying a
// control's required_types) doesn't need the full richness of OSCAL's
// component/subject/party graph to be a faithful, importable assessment
// result.

type oscalMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

// oscalSubject identifies what an observation was made about (here: the
// Fides organization/framework being assessed).
type oscalSubject struct {
	SubjectUUID string `json:"subject-uuid"`
	Type        string `json:"type"`
	Title       string `json:"title,omitempty"`
}

// oscalRelevantEvidence points at the underlying Fides evidence (attestation
// type) that backs an observation.
type oscalRelevantEvidence struct {
	Description string `json:"description"`
}

type oscalObservation struct {
	UUID             string                  `json:"uuid"`
	Description      string                  `json:"description"`
	Methods          []string                `json:"methods"`
	Collected        string                  `json:"collected"`
	Subjects         []oscalSubject          `json:"subjects,omitempty"`
	RelevantEvidence []oscalRelevantEvidence `json:"relevant-evidence,omitempty"`
}

type oscalStatus struct {
	State string `json:"state"`
}

// oscalTarget ties a finding to the control it assesses. TargetID is the
// Fides control key (e.g. "SOC2-CC6.1"), which for NIST-800-53 controls maps
// directly onto the catalog's control identifiers.
type oscalTarget struct {
	Type     string      `json:"type"`
	TargetID string      `json:"target-id"`
	Status   oscalStatus `json:"status"`
}

type oscalRelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalFinding struct {
	UUID                string                    `json:"uuid"`
	Title               string                    `json:"title"`
	Description         string                    `json:"description"`
	Target              oscalTarget               `json:"target"`
	RelatedObservations []oscalRelatedObservation `json:"related-observations,omitempty"`
}

// oscalControlSelection selects the controls in scope for the result. Fides
// reports assess every control imported for the framework, so we use
// include-all rather than enumerating control IDs twice.
type oscalControlSelection struct {
	IncludeAll map[string]any `json:"include-all"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            string                `json:"start"`
	ReviewedControls oscalReviewedControls `json:"reviewed-controls"`
	Observations     []oscalObservation    `json:"observations,omitempty"`
	Findings         []oscalFinding        `json:"findings"`
}

type oscalAssessmentResults struct {
	UUID     string        `json:"uuid"`
	Metadata oscalMetadata `json:"metadata"`
	Results  []oscalResult `json:"results"`
}

// oscalDocument is the OSCAL top-level envelope: assessment-results JSON
// documents are always wrapped in a single root property.
type oscalDocument struct {
	AssessmentResults oscalAssessmentResults `json:"assessment-results"`
}

// buildOSCALAssessmentResults maps a Fides framework report (controls, their
// required evidence types, and whether each is currently satisfied) into an
// OSCAL 1.x assessment-results document. One observation is emitted per
// distinct evidence type collected (compliant) across the report's controls,
// and one finding per control, cross-referencing the observations that back
// it.
func buildOSCALAssessmentResults(framework string, controls []reportControl) oscalDocument {
	now := time.Now().UTC().Format(time.RFC3339)

	// One observation per distinct required evidence type actually present
	// (compliant) anywhere among the report's controls, so findings can
	// cross-reference the evidence that satisfies them without duplicating
	// an observation per control.
	obsUUIDByType := map[string]string{}
	observations := []oscalObservation{}
	for _, c := range controls {
		for _, t := range c.RequiredTypes {
			if _, seen := obsUUIDByType[t]; seen {
				continue
			}
			if containsString(c.MissingTypes, t) {
				continue // not compliant evidence, no observation to attach
			}
			obsUUID := uuid.New().String()
			obsUUIDByType[t] = obsUUID
			observations = append(observations, oscalObservation{
				UUID:        obsUUID,
				Description: "Compliant " + t + " evidence collected by Fides",
				Methods:     []string{"TEST"},
				Collected:   now,
				RelevantEvidence: []oscalRelevantEvidence{
					{Description: "Fides attestation type: " + t},
				},
			})
		}
	}

	findings := make([]oscalFinding, 0, len(controls))
	for _, c := range controls {
		state := "not-satisfied"
		if c.EvidenceSatisfied {
			state = "satisfied"
		}
		var related []oscalRelatedObservation
		for _, t := range c.RequiredTypes {
			if obsUUID, ok := obsUUIDByType[t]; ok {
				related = append(related, oscalRelatedObservation{ObservationUUID: obsUUID})
			}
		}
		findings = append(findings, oscalFinding{
			UUID:        uuid.New().String(),
			Title:       c.Name,
			Description: c.Key + ": " + c.Name,
			Target: oscalTarget{
				Type:     "objective-id",
				TargetID: c.Key,
				Status:   oscalStatus{State: state},
			},
			RelatedObservations: related,
		})
	}

	return oscalDocument{
		AssessmentResults: oscalAssessmentResults{
			UUID: uuid.New().String(),
			Metadata: oscalMetadata{
				Title:        "Fides Assessment Results: " + framework,
				LastModified: now,
				Version:      "1.0.0",
				OSCALVersion: "1.1.2",
			},
			Results: []oscalResult{
				{
					UUID:        uuid.New().String(),
					Title:       framework + " compliance assessment",
					Description: "Automated assessment of " + framework + " controls against evidence collected by Fides.",
					Start:       now,
					ReviewedControls: oscalReviewedControls{
						ControlSelections: []oscalControlSelection{{IncludeAll: map[string]any{}}},
					},
					Observations: observations,
					Findings:     findings,
				},
			},
		},
	}
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
