package api

import (
	"net/http"

	"github.com/google/uuid"
)

// Archiving retires an environment from the compliance picture without
// deleting it. The row and every child record — snapshots, policies,
// allowlists — stay exactly where they are, and the environment still resolves
// by id, so anything already pointing at it keeps working. What changes is
// accounting: it leaves the control-coverage denominator, the OSCAL report,
// the "enforce everywhere" target list, and the default environment listing.
//
// This exists because coverage divided by count(*) of environments, and the
// e2e suite creates one per run and deletes nothing. Five abandoned runs had
// DORA reading 6/15 = 40% when the real figure was 6/10 — a compliance number
// that fell every Monday because a test ran.
//
// Deleting them was the obvious alternative and the wrong one: an environment
// owns evidence, and evidence is not deleted to improve a percentage.

func (s *Server) handleArchiveEnvironment(w http.ResponseWriter, r *http.Request) {
	s.setEnvironmentArchived(w, r, true)
}

func (s *Server) handleUnarchiveEnvironment(w http.ResponseWriter, r *http.Request) {
	s.setEnvironmentArchived(w, r, false)
}

func (s *Server) setEnvironmentArchived(w http.ResponseWriter, r *http.Request, archived bool) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid environment id", http.StatusBadRequest)
		return
	}
	// org_id in the WHERE, never from the request: the caller names an id, the
	// token decides whose tenant it is looked for in.
	res, err := s.q(r.Context()).ExecContext(r.Context(),
		`UPDATE environments SET archived = $1 WHERE id = $2 AND org_id = $3`, archived, id, p.OrgID)
	if err != nil {
		internalError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "archived": archived})
}
