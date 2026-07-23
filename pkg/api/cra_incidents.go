package api

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// severityRank orders scanner severity labels so the highest per CVE can be
// chosen and the report sorted by seriousness.
func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

type craIncident struct {
	CVE          string    `json:"cve"`
	MaxSeverity  string    `json:"max_severity"`
	FirstSeen    time.Time `json:"first_seen"`
	Artifacts    int       `json:"affected_artifacts"`
	Environments []string  `json:"environments"`
	artifactSet  map[string]bool
	envSet       map[string]bool
}

// handleCRAIncidents produces the EU Cyber Resilience Act 24-hour reporting set:
// exploitable vulnerabilities (not suppressed by a not_affected VEX statement)
// discovered in the window, each with its affected artifacts and the
// environments currently running them. It is the evidence an operator files for
// the CRA Art. 14 exploited-vulnerability / severe-incident obligation.
// GET /api/v1/reports/cra-incidents?hours=24
func (s *Server) handleCRAIncidents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*90 {
			hours = n
		}
	}

	// Flat rows of (cve, artifact, severity, discovered, environment) for
	// non-suppressed vulnerabilities in the window; aggregated per CVE below. The
	// environments join is org-scoped (artifacts.sha256 is a global key).
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT av.cve_id, av.artifact_sha256, av.severity, av.created_at, e.name
		 FROM artifact_vulnerabilities av
		 LEFT JOIN snapshot_artifacts sa ON sa.artifact_sha256 = av.artifact_sha256 AND sa.stopped_at IS NULL
		 LEFT JOIN environment_snapshots es ON es.id = sa.snapshot_id
		 LEFT JOIN environments e ON e.id = es.environment_id AND e.org_id = $1
		 WHERE av.org_id = $1
		   AND av.created_at > now() - make_interval(hours => $2)
		   AND NOT EXISTS (
		     SELECT 1 FROM vex_statements vx
		     WHERE vx.org_id = av.org_id AND vx.cve_id = av.cve_id
		       AND vx.status = 'not_affected'
		       AND (vx.product = '' OR vx.product = av.artifact_sha256))
		 ORDER BY av.cve_id`, orgID, hours)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	byCVE := map[string]*craIncident{}
	order := []string{}
	for rows.Next() {
		var cve, sha, sev string
		var created time.Time
		var env *string
		if err := rows.Scan(&cve, &sha, &sev, &created, &env); err != nil {
			internalError(w, err)
			return
		}
		inc, exists := byCVE[cve]
		if !exists {
			inc = &craIncident{CVE: cve, MaxSeverity: sev, FirstSeen: created,
				artifactSet: map[string]bool{}, envSet: map[string]bool{}}
			byCVE[cve] = inc
			order = append(order, cve)
		}
		if severityRank(sev) > severityRank(inc.MaxSeverity) {
			inc.MaxSeverity = sev
		}
		if created.Before(inc.FirstSeen) {
			inc.FirstSeen = created
		}
		inc.artifactSet[sha] = true
		if env != nil {
			inc.envSet[*env] = true
		}
	}

	reportable := make([]*craIncident, 0, len(order))
	for _, cve := range order {
		inc := byCVE[cve]
		inc.Artifacts = len(inc.artifactSet)
		inc.Environments = []string{}
		for e := range inc.envSet {
			inc.Environments = append(inc.Environments, e)
		}
		reportable = append(reportable, inc)
	}
	// Most serious first, then most recent.
	sort.SliceStable(reportable, func(i, j int) bool {
		ri, rj := severityRank(reportable[i].MaxSeverity), severityRank(reportable[j].MaxSeverity)
		if ri != rj {
			return ri > rj
		}
		return reportable[i].FirstSeen.After(reportable[j].FirstSeen)
	})

	// Distinct CVEs in the window that WERE suppressed by VEX — the "focus on
	// exploitable" number, useful to show auditors what was triaged out.
	var suppressed int
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(DISTINCT av.cve_id) FROM artifact_vulnerabilities av
		 WHERE av.org_id = $1 AND av.created_at > now() - make_interval(hours => $2)
		   AND EXISTS (
		     SELECT 1 FROM vex_statements vx
		     WHERE vx.org_id = av.org_id AND vx.cve_id = av.cve_id
		       AND vx.status = 'not_affected'
		       AND (vx.product = '' OR vx.product = av.artifact_sha256))`, orgID, hours).Scan(&suppressed); err != nil {
		internalError(w, err)
		return
	}

	writeJSON(w, map[string]any{
		"window_hours":         hours,
		"obligation":           "EU Cyber Resilience Act (Regulation (EU) 2024/2847) Art. 14 — report actively exploited vulnerabilities / severe incidents within 24 hours",
		"reportable":           reportable,
		"reportable_count":     len(reportable),
		"vex_suppressed_count": suppressed,
	})
}
