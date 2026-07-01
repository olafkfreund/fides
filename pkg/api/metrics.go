package api

import (
	"net/http"
	"strconv"
)

// handleDoraMetrics returns DORA-style delivery metrics for the tenant over a
// window (default 30 days): deployment frequency (snapshots), trail throughput,
// and the attestation compliance rate (a proxy for change-failure rate).
func (s *Server) handleDoraMetrics(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}

	var deployments, trails, compliant, total int
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(*) FROM environment_snapshots es JOIN environments e ON e.id = es.environment_id
		 WHERE e.org_id = $1 AND es.created_at > now() - make_interval(days => $2)`, orgID, days).Scan(&deployments); err != nil {
		internalError(w, err)
		return
	}
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(*) FROM trails tr JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND tr.created_at > now() - make_interval(days => $2)`, orgID, days).Scan(&trails); err != nil {
		internalError(w, err)
		return
	}
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(*) FILTER (WHERE at.is_compliant), count(*)
		 FROM attestations at JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND at.created_at > now() - make_interval(days => $2)`, orgID, days).Scan(&compliant, &total); err != nil {
		internalError(w, err)
		return
	}

	complianceRate := 1.0
	if total > 0 {
		complianceRate = float64(compliant) / float64(total)
	}
	writeJSON(w, map[string]any{
		"window_days":                  days,
		"deployments":                  deployments,
		"deployment_frequency_per_day": float64(deployments) / float64(days),
		"trails":                       trails,
		"attestations":                 total,
		"compliance_rate":              complianceRate,
		"change_failure_rate":          1 - complianceRate,
	})
}

// handleDeploymentFrequency returns per-environment weekly deployment counts
// (snapshots) for the last N weeks, for the Kosli-style frequency chart.
func (s *Server) handleDeploymentFrequency(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	weeks := 12
	if v := r.URL.Query().Get("weeks"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 53 {
			weeks = n
		}
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT e.name, to_char(date_trunc('week', es.created_at), 'IYYY-"W"IW') AS week, count(*)
		 FROM environment_snapshots es JOIN environments e ON e.id = es.environment_id
		 WHERE e.org_id = $1 AND es.created_at > now() - make_interval(weeks => $2)
		 GROUP BY e.name, week ORDER BY week`, orgID, weeks)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var env, week string
		var count int
		if err := rows.Scan(&env, &week, &count); err != nil {
			internalError(w, err)
			return
		}
		out = append(out, map[string]any{"environment": env, "week": week, "deployments": count})
	}
	writeJSON(w, out)
}
