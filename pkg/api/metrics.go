package api

import (
	"database/sql"
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

	// Lead time for changes: median time from the change being committed to its
	// deployment anchor. Uses the git commit timestamp (git_committed_at) when
	// recorded — true code-to-prod lead time — and falls back to the trail's
	// creation time (pipeline lead time) when it is not.
	var leadSecs sql.NullFloat64
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (da.created_at - COALESCE(tr.git_committed_at, tr.created_at))))
		 FROM deployment_anchors da JOIN trails tr ON tr.id = da.trail_id
		 WHERE da.org_id = $1 AND da.created_at > now() - make_interval(days => $2)
		   AND da.created_at >= COALESCE(tr.git_committed_at, tr.created_at)`, orgID, days).Scan(&leadSecs); err != nil {
		internalError(w, err)
		return
	}

	// MTTR / time-to-restore: median time from a non-compliant deployment to the
	// next compliant deployment of the same service (deployment_anchors.ci_name).
	// deployment_anchors.compliant is the failure signal Fides already records.
	var mttrSecs sql.NullFloat64
	var restored int
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`WITH gaps AS (
		     SELECT compliant, EXTRACT(EPOCH FROM (
		         min(created_at) FILTER (WHERE compliant) OVER (
		             PARTITION BY ci_name ORDER BY created_at
		             ROWS BETWEEN 1 FOLLOWING AND UNBOUNDED FOLLOWING) - created_at)) AS restore_secs
		     FROM deployment_anchors
		     WHERE org_id = $1 AND ci_name IS NOT NULL
		       AND created_at > now() - make_interval(days => $2))
		 SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY restore_secs), count(*)
		 FROM gaps WHERE NOT compliant AND restore_secs IS NOT NULL`, orgID, days).Scan(&mttrSecs, &restored); err != nil {
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
		"lead_time_hours":              nullHours(leadSecs),
		"mttr_hours":                   nullHours(mttrSecs),
		"mttr_restored_count":          restored,
	})
}

// nullHours converts a nullable second count into a rounded-hours pointer, or
// nil when there is no data (so the JSON is null, not a fake 0).
func nullHours(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	h := v.Float64 / 3600
	return &h
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
