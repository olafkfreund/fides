package api

import (
	_ "embed"
	"net/http"
)

//go:embed assets/admin.html
var adminConsoleHTML []byte

// handleAdminConsolePage serves the unified Go-served admin console. The page
// shell is public; its API calls are authenticated by the session cookie.
func (s *Server) handleAdminConsolePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(adminConsoleHTML)
}
