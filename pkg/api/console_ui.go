package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
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
	sum, err := s.buildConsoleSummary(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// handleConsoleStream pushes the console summary as Server-Sent Events every few
// seconds so the dashboard updates without repeated polling. Clients that can't
// stream fall back to GET /api/v1/console/summary.
func (s *Server) handleConsoleStream(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // don't let the ingress/proxy buffer the stream
	ctx := r.Context()

	send := func() bool {
		sum, err := s.buildConsoleSummary(ctx, orgID)
		if err != nil {
			return true // transient DB error — keep the stream open, try next tick
		}
		b, _ := json.Marshal(sum)
		if _, werr := fmt.Fprintf(w, "data: %s\n\n", b); werr != nil {
			return false
		}
		fl.Flush()
		return true
	}
	if !send() {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

// buildConsoleSummary runs the summary queries for one org (shared by the JSON
// endpoint and the SSE stream).
func (s *Server) buildConsoleSummary(ctx context.Context, orgID uuid.UUID) (consoleSummary, error) {
	q := s.q(ctx)
	var sum consoleSummary

	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifacts a
		 JOIN trails t ON t.id = a.trail_id JOIN flows f ON f.id = t.flow_id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.Artifacts); err != nil {
		return sum, err
	}

	// Total, compliant, and last-24h check counts in one pass.
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE at.is_compliant),
		        COUNT(*) FILTER (WHERE at.created_at > now() - interval '24 hours')
		 FROM attestations at
		 JOIN trails tr ON tr.id = at.trail_id JOIN flows f ON f.id = tr.flow_id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.ChecksTotal, &sum.Compliant, &sum.ChecksLast24h); err != nil {
		return sum, err
	}

	// AI evaluations (LLM compliance assessments), scoped via attestation->trail->flow.
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM llm_assessments la
		 JOIN attestations att ON la.attestation_id = att.id
		 JOIN trails tr ON att.trail_id = tr.id JOIN flows f ON tr.flow_id = f.id
		 WHERE f.org_id = $1`, orgID).Scan(&sum.AIEvaluations); err != nil {
		return sum, err
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
		return sum, err
	}
	defer rows.Close()
	sum.Recent = []consoleRecentCheck{}
	for rows.Next() {
		var c consoleRecentCheck
		var created time.Time
		if err := rows.Scan(&c.Name, &c.Kind, &c.Compliant, &created); err != nil {
			return sum, err
		}
		c.At = created.UTC().Format(time.RFC3339)
		sum.Recent = append(sum.Recent, c)
	}

	sum.ServerTime = time.Now().UTC().Format(time.RFC3339)
	return sum, rows.Err()
}

// compliancePct is the integer percentage of compliant checks over total,
// rounded half-up; 0 when there are no checks.
func compliancePct(compliant, total int) int {
	if total <= 0 {
		return 0
	}
	return (compliant*100 + total/2) / total
}
