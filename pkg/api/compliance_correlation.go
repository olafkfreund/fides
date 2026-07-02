package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"

	"github.com/google/uuid"
)

// maxCorrelationTrails bounds how many trails' change-gate risk scores are
// computed per request, so a busy org over a wide window can't turn this
// endpoint into an unbounded N+1 query storm.
const maxCorrelationTrails = 500

// PeriodRaw holds the raw, per-period counts pulled from the DB that feed the
// DORA↔compliance correlation view: deployment volume, attestation pass/fail
// counts (the change-failure-rate proxy also used by handleDoraMetrics), and
// the individual change-gate risk scores for trails created in that period.
type PeriodRaw struct {
	Period                   string
	Deployments              int
	AttestationsTotal        int
	AttestationsNonCompliant int
	RiskScores               []int
}

// PeriodCorrelation is one row of the compliance-correlation report: DORA
// delivery signals overlaid with the compliance/GRC signals (change-gate risk
// and control coverage) for the same period.
type PeriodCorrelation struct {
	Period             string  `json:"period"`
	Deployments        int     `json:"deployments"`
	ChangeFailureRate  float64 `json:"change_failure_rate"`
	AvgRiskScore       float64 `json:"avg_risk_score"`
	ControlCoveragePct float64 `json:"control_coverage_pct"`
}

// aggregateComplianceCorrelation merges per-period DORA counts and change-gate
// risk scores with the org's current control-coverage percentage into the
// correlation report rows. It is a pure function (no DB access) so the
// aggregation math can be unit tested with synthetic inputs.
//
// controlCoveragePct is applied to every period because control coverage is a
// point-in-time property of the org's environments/policies today, not a
// value Fides tracks historically per period.
func aggregateComplianceCorrelation(periods []PeriodRaw, controlCoveragePct float64) []PeriodCorrelation {
	out := make([]PeriodCorrelation, 0, len(periods))
	for _, p := range periods {
		changeFailureRate := 0.0
		if p.AttestationsTotal > 0 {
			changeFailureRate = float64(p.AttestationsNonCompliant) / float64(p.AttestationsTotal)
		}
		avgRisk := 0.0
		if n := len(p.RiskScores); n > 0 {
			sum := 0
			for _, rs := range p.RiskScores {
				sum += rs
			}
			avgRisk = float64(sum) / float64(n)
		}
		out = append(out, PeriodCorrelation{
			Period:             p.Period,
			Deployments:        p.Deployments,
			ChangeFailureRate:  changeFailureRate,
			AvgRiskScore:       avgRisk,
			ControlCoveragePct: controlCoveragePct,
		})
	}
	return out
}

// currentControlCoveragePct returns the org's overall control-coverage
// percentage right now: the fraction of (active control, environment) pairs
// where the control's required evidence types are enforced by an enabled
// environment policy. Same enforcement semantics as handleControlsCoverage,
// collapsed to a single ratio.
func (s *Server) currentControlCoveragePct(ctx context.Context, orgID uuid.UUID) (float64, error) {
	var enforced, total int
	err := s.q(ctx).QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE enforced), count(*)
		FROM (
		  SELECT EXISTS (
		    SELECT 1 FROM environment_policies p
		    WHERE p.environment_id = e.id AND p.enabled AND c.required_types <@ p.required_types
		  ) AS enforced
		  FROM controls c
		  CROSS JOIN environments e
		  WHERE c.org_id = $1 AND e.org_id = $1 AND NOT c.archived
		) pairs`, orgID).Scan(&enforced, &total)
	if err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}
	return float64(enforced) / float64(total), nil
}

// handleComplianceCorrelation returns the DORA↔compliance correlation view:
// per weekly period over the window, deployment frequency and change-failure
// rate (delivery signals) alongside the average change-gate risk score and
// current control-coverage percentage (GRC signals) — so teams can see, e.g.,
// whether periods of high deployment frequency correlate with rising risk
// scores or shrinking control coverage.
func (s *Server) handleComplianceCorrelation(w http.ResponseWriter, r *http.Request) {
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
	ctx := r.Context()

	deployByPeriod := map[string]int{}
	drows, err := s.q(ctx).QueryContext(ctx,
		`SELECT to_char(date_trunc('week', es.created_at), 'IYYY-"W"IW') AS period, count(*)
		 FROM environment_snapshots es JOIN environments e ON e.id = es.environment_id
		 WHERE e.org_id = $1 AND es.created_at > now() - make_interval(days => $2)
		 GROUP BY period`, orgID, days)
	if err != nil {
		internalError(w, err)
		return
	}
	for drows.Next() {
		var period string
		var count int
		if err := drows.Scan(&period, &count); err != nil {
			drows.Close()
			internalError(w, err)
			return
		}
		deployByPeriod[period] = count
	}
	drows.Close()

	type attCounts struct{ nonCompliant, total int }
	attByPeriod := map[string]attCounts{}
	arows, err := s.q(ctx).QueryContext(ctx,
		`SELECT to_char(date_trunc('week', at.created_at), 'IYYY-"W"IW') AS period,
		        count(*) FILTER (WHERE NOT at.is_compliant), count(*)
		 FROM attestations at JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND at.created_at > now() - make_interval(days => $2)
		 GROUP BY period`, orgID, days)
	if err != nil {
		internalError(w, err)
		return
	}
	for arows.Next() {
		var period string
		var nonCompliant, total int
		if err := arows.Scan(&period, &nonCompliant, &total); err != nil {
			arows.Close()
			internalError(w, err)
			return
		}
		attByPeriod[period] = attCounts{nonCompliant: nonCompliant, total: total}
	}
	arows.Close()

	riskByPeriod := map[string][]int{}
	trows, err := s.q(ctx).QueryContext(ctx,
		`SELECT tr.id, to_char(date_trunc('week', tr.created_at), 'IYYY-"W"IW') AS period
		 FROM trails tr JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1 AND tr.created_at > now() - make_interval(days => $2)
		 ORDER BY tr.created_at DESC LIMIT $3`, orgID, days, maxCorrelationTrails)
	if err != nil {
		internalError(w, err)
		return
	}
	var trailIDs []uuid.UUID
	var trailPeriods []string
	for trows.Next() {
		var id uuid.UUID
		var period string
		if err := trows.Scan(&id, &period); err != nil {
			trows.Close()
			internalError(w, err)
			return
		}
		trailIDs = append(trailIDs, id)
		trailPeriods = append(trailPeriods, period)
	}
	trows.Close()
	for i, id := range trailIDs {
		gate, err := s.computeChangeGate(ctx, orgID, id)
		if err != nil {
			internalError(w, err)
			return
		}
		if rs, ok := gate["risk_score"].(int); ok {
			period := trailPeriods[i]
			riskByPeriod[period] = append(riskByPeriod[period], rs)
		}
	}

	coveragePct, err := s.currentControlCoveragePct(ctx, orgID)
	if err != nil {
		internalError(w, err)
		return
	}

	periodSet := map[string]bool{}
	for p := range deployByPeriod {
		periodSet[p] = true
	}
	for p := range attByPeriod {
		periodSet[p] = true
	}
	for p := range riskByPeriod {
		periodSet[p] = true
	}
	periods := make([]string, 0, len(periodSet))
	for p := range periodSet {
		periods = append(periods, p)
	}
	sort.Strings(periods)

	raw := make([]PeriodRaw, 0, len(periods))
	for _, p := range periods {
		a := attByPeriod[p]
		raw = append(raw, PeriodRaw{
			Period:                   p,
			Deployments:              deployByPeriod[p],
			AttestationsTotal:        a.total,
			AttestationsNonCompliant: a.nonCompliant,
			RiskScores:               riskByPeriod[p],
		})
	}

	writeJSON(w, map[string]any{
		"window_days": days,
		"periods":     aggregateComplianceCorrelation(raw, coveragePct),
	})
}
