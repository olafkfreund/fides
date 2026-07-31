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
	writeJSON(w, s.trainingRecords(r, orgID))
}

// trainingRecords is shared by the list endpoint and the audit pack.
func (s *Server) trainingRecords(r *http.Request, orgID uuid.UUID) []map[string]any {
	list := []map[string]any{}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT person, course, completed_at, COALESCE(notes, '')
		 FROM training_records WHERE org_id = $1 ORDER BY completed_at DESC`, orgID)
	if err != nil {
		return list
	}
	defer rows.Close()
	for rows.Next() {
		var person, course, notes string
		var completed time.Time
		if rows.Scan(&person, &course, &completed, &notes) == nil {
			list = append(list, map[string]any{
				"person": person, "course": course, "completed_at": completed, "notes": notes,
			})
		}
	}
	return list
}
