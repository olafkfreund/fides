package api

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"net/http"
	"time"
)

//go:embed assets/servicenow.html
var serviceNowAdminHTML []byte

// handleServiceNowAdminPage serves the standalone ServiceNow admin page. The
// page shell is public; its API calls are authenticated by the session cookie.
func (s *Server) handleServiceNowAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(serviceNowAdminHTML)
}

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
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT event_type, status, attempts, COALESCE(last_error, ''), created_at, delivered_at
		 FROM integration_events WHERE org_id = $1 ORDER BY created_at DESC LIMIT 50`, orgID)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
