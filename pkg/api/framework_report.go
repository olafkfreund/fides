package api

import (
	"net/http"
	"time"

	"github.com/lib/pq"
)

// reportControl is one control's evidence/coverage state within a framework
// report, shared by the default human-readable JSON output and the OSCAL
// assessment-results export.
type reportControl struct {
	Key               string
	Name              string
	RequiredTypes     []string
	MissingTypes      []string
	EvidenceSatisfied bool
	EnforcedIn        []string
	Coverage          float64
}

// handleFrameworkReport produces an auditor-ready, framework-scoped report: each
// control in the framework, whether it is satisfied by compliant evidence, and
// how many environments enforce it (coverage) — plus a summary.
//
// By default the response is Fides' own JSON report shape. Passing
// ?format=oscal instead produces a NIST OSCAL 1.x assessment-results JSON
// document mapping the same controls to their collected evidence, for
// machine-readable submission (e.g. FedRAMP 20x).
func (s *Server) handleFrameworkReport(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	framework := r.PathValue("framework")
	if framework == "" {
		http.Error(w, "framework is required", http.StatusBadRequest)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "oscal" {
		http.Error(w, "unsupported format (supported: oscal)", http.StatusBadRequest)
		return
	}

	// Compliant attestation types present anywhere in the org (evidence pool).
	compliantTypes := map[string]bool{}
	erows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT DISTINCT at.type_name
		 FROM attestations at JOIN trails t ON t.id = at.trail_id JOIN flows f ON f.id = t.flow_id
		 WHERE f.org_id = $1 AND at.is_compliant`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	for erows.Next() {
		var t string
		if err := erows.Scan(&t); err == nil {
			compliantTypes[t] = true
		}
	}
	erows.Close()

	var totalEnvs int
	_ = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(*) FROM environments WHERE org_id = $1`, orgID).Scan(&totalEnvs)

	// Controls in this framework + the environments that enforce each (via a
	// policy whose required_types superset the control's).
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT c.key, c.name, c.required_types, e.name
		 FROM controls c
		 LEFT JOIN environments e ON e.org_id = c.org_id AND EXISTS (
		   SELECT 1 FROM environment_policies p
		   WHERE p.environment_id = e.id AND p.enabled AND c.required_types <@ p.required_types)
		 WHERE c.org_id = $1 AND c.framework = $2 AND NOT c.archived
		 ORDER BY c.key, e.name`, orgID, framework)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type ctl struct {
		Key, Name     string
		RequiredTypes []string
		EnforcedIn    []string
	}
	byKey := map[string]*ctl{}
	order := []string{}
	for rows.Next() {
		var key, name string
		var req pq.StringArray
		var env *string
		if err := rows.Scan(&key, &name, &req, &env); err != nil {
			internalError(w, err)
			return
		}
		c := byKey[key]
		if c == nil {
			c = &ctl{Key: key, Name: name, RequiredTypes: []string(req), EnforcedIn: []string{}}
			byKey[key] = c
			order = append(order, key)
		}
		if env != nil {
			c.EnforcedIn = append(c.EnforcedIn, *env)
		}
	}

	reportControls := make([]reportControl, 0, len(order))
	satisfied, withCoverage := 0, 0
	for _, k := range order {
		c := byKey[k]
		missing := []string{}
		for _, t := range c.RequiredTypes {
			if !compliantTypes[t] {
				missing = append(missing, t)
			}
		}
		evidenceSatisfied := len(missing) == 0
		if evidenceSatisfied {
			satisfied++
		}
		coverage := 0.0
		if totalEnvs > 0 {
			coverage = float64(len(c.EnforcedIn)) / float64(totalEnvs)
		}
		if len(c.EnforcedIn) > 0 {
			withCoverage++
		}
		reportControls = append(reportControls, reportControl{
			Key: c.Key, Name: c.Name, RequiredTypes: c.RequiredTypes,
			MissingTypes: missing, EvidenceSatisfied: evidenceSatisfied,
			EnforcedIn: c.EnforcedIn, Coverage: coverage,
		})
	}

	if format == "oscal" {
		writeJSON(w, buildOSCALAssessmentResults(framework, reportControls))
		return
	}

	controls := make([]map[string]any, 0, len(reportControls))
	for _, c := range reportControls {
		controls = append(controls, map[string]any{
			"control": c.Key, "name": c.Name, "required_types": c.RequiredTypes,
			"evidence_satisfied": c.EvidenceSatisfied, "missing_types": c.MissingTypes,
			"enforced_in": c.EnforcedIn, "coverage": c.Coverage,
		})
	}

	writeJSON(w, map[string]any{
		"framework":          framework,
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
		"total_environments": totalEnvs,
		"summary": map[string]any{
			"total_controls":     len(order),
			"evidence_satisfied": satisfied,
			"with_coverage":      withCoverage,
			"coverage_pct":       pct(satisfied, len(order)),
		},
		"controls": controls,
	})
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
