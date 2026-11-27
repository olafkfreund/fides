package api

import (
	"database/sql"
	"net/http"
	"time"
)

type integrationEventView struct {
	EventType string  `json:"event_type"`
	Status    string  `json:"status"`
	Attempts  int     `json:"attempts"`
	LastError string  `json:"last_error"`
	CreatedAt string  `json:"created_at"`
	Delivered *string `json:"delivered_at,omitempty"`
}

// handleServiceNowEvents returns the most recent integration events for the
// tenant (powers the admin page's monitor view).
func (s *Server) handleServiceNowEvents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, ok := newListPage(w, r, orgID, timeKey("created_at"), uuidKey("id"), true)
	if !ok {
		return
	}
	rows, err := s.queryPage(r, page,
		`SELECT event_type, status, attempts, COALESCE(last_error, ''), created_at, delivered_at /* page keys */
		 FROM integration_events WHERE org_id = $1`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	out := []integrationEventView{}
	for rows.Next() {
		var e integrationEventView
		var created time.Time
		var delivered sql.NullTime
		if err := rows.Scan(&e.EventType, &e.Status, &e.Attempts, &e.LastError, &created, &delivered); err != nil {
			internalError(w, err)
			return
		}
		e.CreatedAt = created.UTC().Format(time.RFC3339)
		if delivered.Valid {
			d := delivered.Time.UTC().Format(time.RFC3339)
			e.Delivered = &d
		}
		out = append(out, e)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	page.write(w, out)
}
