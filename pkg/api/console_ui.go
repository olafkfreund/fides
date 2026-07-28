package api

import (
	"encoding/json"
	"net/http"
	"time"
)

type consoleRecentCheck struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Compliant bool   `json:"compliant"`
	At        string `json:"at"`
}

// consoleSummary is the single pollable snapshot that powers the console's
// top-line numbers and the live check stream.
type consoleSummary struct {
	Artifacts     int                  `json:"artifacts"`
	ChecksTotal   int                  `json:"checksTotal"`
	ChecksLast24h int                  `json:"checksLast24h"`
	Compliant     int                  `json:"compliant"`
	NonCompliant  int                  `json:"nonCompliant"`
	CompliancePct int                  `json:"compliancePct"`
	AIEvaluations int                  `json:"aiEvaluations"`
	Recent        []consoleRecentCheck `json:"recent"`
	ServerTime    string               `json:"serverTime"`
}

// handleConsoleSummary aggregates tenant-scoped counts and the most recent
// attestations ("checks") into one response the console polls every few seconds.
func (s *Server) handleConsoleSummary(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	q := s.q(ctx)
	var sum consoleSummary

	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifacts a
		 JOIN trails t ON t.id = a.trail_id JOIN flows f ON f.id = t.flow_id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.Artifacts); err != nil {
		internalError(w, err)
		return
	}

	// Total, compliant, and last-24h check counts in one pass.
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE at.is_compliant),
		        COUNT(*) FILTER (WHERE at.created_at > now() - interval '24 hours')
		 FROM attestations at
		 JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.ChecksTotal, &sum.Compliant, &sum.ChecksLast24h); err != nil {
		internalError(w, err)
		return
	}

	// AI evaluations (LLM compliance assessments), scoped via attestation->trail->flow.
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM llm_assessments la
		 JOIN attestations att ON la.attestation_id = att.id
		 JOIN trails tr ON att.trail_id = tr.id JOIN flows f ON tr.flow_id = f.id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.AIEvaluations); err != nil {
		internalError(w, err)
		return
	}

	sum.NonCompliant = sum.ChecksTotal - sum.Compliant
	sum.CompliancePct = compliancePct(sum.Compliant, sum.ChecksTotal)

	rows, err := q.QueryContext(ctx,
		`SELECT at.name, at.type_name, at.is_compliant, at.created_at
		 FROM attestations at
		 JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1
		 ORDER BY at.created_at DESC LIMIT 25`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	sum.Recent = []consoleRecentCheck{}
	for rows.Next() {
		var c consoleRecentCheck
		var created time.Time
		if err := rows.Scan(&c.Name, &c.Kind, &c.Compliant, &created); err != nil {
			internalError(w, err)
			return
		}
		c.At = created.UTC().Format(time.RFC3339)
		sum.Recent = append(sum.Recent, c)
	}

	sum.ServerTime = time.Now().UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// compliancePct is the integer percentage of compliant checks over total,
// rounded half-up; 0 when there are no checks.
func compliancePct(compliant, total int) int {
	if total <= 0 {
		return 0
	}
	return (compliant*100 + total/2) / total
}
