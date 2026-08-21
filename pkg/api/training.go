package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type recordTrainingReq struct {
	Person      string `json:"person"`
	Course      string `json:"course"`
	CompletedAt string `json:"completed_at"` // RFC3339; defaults to now
	Notes       string `json:"notes"`
}

// handleRecordTraining records a completed training/awareness event as audit
// evidence (org-scoped).
func (s *Server) handleRecordTraining(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req recordTrainingReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Person) == "" || strings.TrimSpace(req.Course) == "" {
		http.Error(w, "person and course are required", http.StatusBadRequest)
		return
	}
	completed := time.Now()
	if req.CompletedAt != "" {
		if t, err := time.Parse(time.RFC3339, req.CompletedAt); err == nil {
			completed = t
		} else {
			http.Error(w, "completed_at must be RFC3339", http.StatusBadRequest)
			return
		}
	}
	var id uuid.UUID
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`INSERT INTO training_records (id, org_id, person, course, completed_at, notes)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		uuid.New(), orgID, req.Person, req.Course, completed, req.Notes).Scan(&id)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id": id, "person": req.Person, "course": req.Course, "completed_at": completed,
	})
}

// handleListTraining lists the org's training records, newest first.
func (s *Server) handleListTraining(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	recs, err := s.trainingRecords(r, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, recs)
}

// trainingRecords is shared by the list endpoint and the audit pack.
//
// It returns an error rather than a best-effort slice because the audit pack is
// one of its callers: a short read there produces an evidence bundle that is
// missing training records with nothing to say so, which is indistinguishable
// from an organisation that never did the training.
func (s *Server) trainingRecords(r *http.Request, orgID uuid.UUID) ([]map[string]any, error) {
	list := []map[string]any{}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT person, course, completed_at, COALESCE(notes, '')
		 FROM training_records WHERE org_id = $1 ORDER BY completed_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var person, course, notes string
		var completed time.Time
		if err := rows.Scan(&person, &course, &completed, &notes); err != nil {
			return nil, err
		}
		list = append(list, map[string]any{
			"person": person, "course": course, "completed_at": completed, "notes": notes,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}
