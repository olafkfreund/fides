package api

import (
	_ "embed"
	"net/http"
)

//go:embed assets/evidence.html
var evidenceVaultHTML []byte

// handleEvidenceVaultPage serves the standalone Evidence Vault page: a
// per-trail/artifact evidence timeline (attestations, gate verdict, chain
// tamper-evidence status). The page shell is public; its API calls are
// authenticated by the session cookie, same pattern as /servicenow and /admin.
func (s *Server) handleEvidenceVaultPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(evidenceVaultHTML)
}
