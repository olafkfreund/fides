package api

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"fides/pkg/ledger"
)

// handleTrailAuditPackage streams a ZIP audit package for a trail: metadata,
// artifacts, attestations, the tamper-evidence chain verdict, and a readable
// report — a self-contained compliance evidence bundle.
func (s *Server) handleTrailAuditPackage(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}

	// Trail metadata (org-scoped via flow).
	var name, repo, commit, branch string
	var created time.Time
	err = s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT tr.name, COALESCE(tr.git_repository,''), COALESCE(tr.git_commit,''), COALESCE(tr.git_branch,''), tr.created_at
		 FROM trails tr JOIN flows f ON f.id = tr.flow_id WHERE tr.id = $1 AND f.org_id = $2`,
		trailID, orgID).Scan(&name, &repo, &commit, &branch, &created)
	if err == sql.ErrNoRows {
		http.Error(w, "trail not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	trail := map[string]any{"id": trailID, "name": name, "git_repository": repo, "git_commit": commit, "git_branch": branch, "created_at": created.UTC().Format(time.RFC3339)}

	artifacts := s.collectRows(r, `SELECT sha256, name, type, created_at FROM artifacts WHERE trail_id = $1 ORDER BY created_at`, trailID,
		[]string{"sha256", "name", "type", "created_at"})

	// Attestations (+ chain entries for the verdict).
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT name, type_name, payload::text, is_compliant, COALESCE(content_hash,''), COALESCE(prev_hash,''), created_at
		 FROM attestations WHERE trail_id = $1 ORDER BY created_at, id`, trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	var attestations []map[string]any
	var entries []ledger.Entry
	for rows.Next() {
		var an, at, payload, ch, ph string
		var compliant bool
		var ts time.Time
		if err := rows.Scan(&an, &at, &payload, &compliant, &ch, &ph, &ts); err != nil {
			rows.Close()
			internalError(w, err)
			return
		}
		attestations = append(attestations, map[string]any{"name": an, "type_name": at, "payload": json.RawMessage(payload), "is_compliant": compliant, "content_hash": ch, "prev_hash": ph, "created_at": ts.UTC().Format(time.RFC3339)})
		entries = append(entries, ledger.Entry{TrailID: trailID.String(), Name: an, TypeName: at, Payload: ledger.CanonicalJSON(payload), IsCompliant: compliant, ContentHash: ch, PrevHash: ph})
	}
	rows.Close()
	verdict := ledger.Verify(entries)

	// Build the ZIP.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(fname string, v any) error {
		f, err := zw.Create(fname)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if err := add("trail.json", trail); err != nil {
		internalError(w, err)
		return
	}
	_ = add("artifacts.json", artifacts)
	_ = add("attestations.json", attestations)
	_ = add("chain-verification.json", verdict)

	if rf, err := zw.Create("report.md"); err == nil {
		fmt.Fprintf(rf, "# Fides Audit Package\n\n")
		fmt.Fprintf(rf, "Trail: %s (%s)\nCommit: %s  Branch: %s\nGenerated from repository: %s\n\n", name, trailID, commit, branch, repo)
		fmt.Fprintf(rf, "Artifacts: %d\nAttestations: %d\n\n", len(artifacts), len(attestations))
		fmt.Fprintf(rf, "## Tamper-evidence chain\n\nValid: %v (checked %d, broken_at %d)\n", verdict.Valid, verdict.Count, verdict.BrokenAt)
		if verdict.Reason != "" {
			fmt.Fprintf(rf, "Reason: %s\n", verdict.Reason)
		}
	}
	if err := zw.Close(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"trail-%s-audit.zip\"", trailID))
	w.Write(buf.Bytes())
}

// collectRows runs a query and returns rows as maps keyed by the given columns.
func (s *Server) collectRows(r *http.Request, query string, arg any, cols []string) []map[string]any {
	out := []map[string]any{}
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, arg)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out
		}
		m := map[string]any{}
		for i, c := range cols {
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out
}
