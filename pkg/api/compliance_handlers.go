package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

func (s *Server) handleCheckCompliance(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := r.URL.Query()
	for _, selector := range query["policy"] {
		if selector != "" {
			http.Error(w, "policy selector is unsupported", http.StatusBadRequest)
			return
		}
	}
	sha := query.Get("sha256")
	if sha == "" {
		http.Error(w, "missing sha256 query param", http.StatusBadRequest)
		return
	}

	var name string
	var trailID sql.NullString
	// The attestation query below is keyed on this trail id, so scoping the
	// artifact scopes the whole answer: a trail reached from an artifact in the
	// caller's org is in the caller's org.
	queryArt := `SELECT name, trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1`
	err := s.q(r.Context()).QueryRowContext(r.Context(), queryArt, sha, orgID).Scan(&name, &trailID)
	if err == sql.ErrNoRows {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}

	isCompliant := true
	var reasons []string

	if trailID.Valid && trailID.String != "" {
		queryAtt := `SELECT name, type_name, is_compliant FROM attestations WHERE trail_id = $1`
		rows, err := s.q(r.Context()).QueryContext(r.Context(), queryAtt, trailID.String)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var attName, typeName string
			var compliant bool
			if err := rows.Scan(&attName, &typeName, &compliant); err != nil {
				internalError(w, err)
				return
			}
			if !compliant {
				isCompliant = false
				reasons = append(reasons, fmt.Sprintf("Failing control: %s (Type: %s)", attName, typeName))
			}
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sha256":     sha,
		"name":       name,
		"compliant":  isCompliant,
		"violations": reasons,
	})
}
