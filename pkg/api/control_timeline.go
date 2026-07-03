package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/lib/pq"
)

// timelineEvent is one point in a control's continuous evidence feed: a single
// attestation of one of the control's required types, with its compliance and
// when it was recorded.
type timelineEvent struct {
	Type      string    `json:"type"`
	Compliant bool      `json:"compliant"`
	TrailID   string    `json:"trail_id"`
	At        time.Time `json:"at"`
}

// controlTimeline is a control's evidence over time (not point-in-time): the
// ordered stream of evidence events plus the most-recent derived status.
type controlTimeline struct {
	Control       string          `json:"control"`
	Name          string          `json:"name"`
	Framework     string          `json:"framework,omitempty"`
	RequiredTypes []string        `json:"required_types"`
	Events        []timelineEvent `json:"events"`
	LatestStatus  string          `json:"latest_status"` // passed | failed | missing
}

// handleControlTimeline turns point-in-time control coverage into a continuous
// control-test evidence feed (#225): for each control it returns the ordered
// stream of evidence (attestations of the control's required types within the
// window) so `fides control timeline` and per-framework reports can show how a
// control's evidence held up over time, not just right now. The stream is
// derived from the immutable attestation chain — so it is tamper-evident by
// construction rather than a separately-mutable results table.
//
// Query params: ?days=N (default 90, clamped to [1,3650]) and ?key=KEY to scope
// to a single control.
func (s *Server) handleControlTimeline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	if days > 3650 {
		days = 3650
	}
	keyFilter := r.URL.Query().Get("key")

	// Load the org's active controls (optionally one).
	crows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT key, name, COALESCE(framework,''), required_types
		 FROM controls
		 WHERE org_id = $1 AND NOT archived AND ($2 = '' OR key = $2)
		 ORDER BY key`, orgID, keyFilter)
	if err != nil {
		internalError(w, err)
		return
	}
	type ctl struct {
		key, name, framework string
		req                  []string
	}
	controls := []ctl{}
	for crows.Next() {
		var c ctl
		var req pq.StringArray
		if err := crows.Scan(&c.key, &c.name, &c.framework, &req); err != nil {
			crows.Close()
			internalError(w, err)
			return
		}
		c.req = []string(req)
		controls = append(controls, c)
	}
	crows.Close()

	out := make([]controlTimeline, 0, len(controls))
	for _, c := range controls {
		t := controlTimeline{
			Control: c.key, Name: c.name, Framework: c.framework,
			RequiredTypes: c.req, Events: []timelineEvent{},
		}
		// The most recent compliance seen per required type, to derive the
		// latest status with the same AND semantics as the change gate.
		latestByType := map[string]bool{}

		if len(c.req) > 0 {
			erows, err := s.q(r.Context()).QueryContext(r.Context(),
				`SELECT at.type_name, at.is_compliant, at.trail_id, at.created_at
				 FROM attestations at
				 JOIN trails t ON t.id = at.trail_id
				 JOIN flows f ON f.id = t.flow_id
				 WHERE f.org_id = $1
				   AND at.type_name = ANY($2)
				   AND at.created_at >= now() - make_interval(days => $3)
				 ORDER BY at.created_at`, orgID, pq.Array(c.req), days)
			if err != nil {
				internalError(w, err)
				return
			}
			for erows.Next() {
				var ev timelineEvent
				var trailID *string
				if err := erows.Scan(&ev.Type, &ev.Compliant, &trailID, &ev.At); err != nil {
					erows.Close()
					internalError(w, err)
					return
				}
				if trailID != nil {
					ev.TrailID = *trailID
				}
				t.Events = append(t.Events, ev)
				latestByType[ev.Type] = ev.Compliant // ordered by created_at ASC, so last wins
			}
			erows.Close()
		}

		t.LatestStatus = deriveControlStatus(c.req, latestByType)
		out = append(out, t)
	}

	writeJSON(w, map[string]any{"window_days": days, "controls": out})
}

// deriveControlStatus applies the change gate's AND semantics to the most-recent
// evidence per type: "missing" if any required type has no evidence in the
// window, "failed" if all are present but one's latest evidence is non-compliant,
// otherwise "passed".
func deriveControlStatus(required []string, latestByType map[string]bool) string {
	if len(required) == 0 {
		return "passed"
	}
	hasFailed := false
	for _, t := range required {
		compliant, present := latestByType[t]
		if !present {
			return "missing"
		}
		if !compliant {
			hasFailed = true
		}
	}
	if hasFailed {
		return "failed"
	}
	return "passed"
}
