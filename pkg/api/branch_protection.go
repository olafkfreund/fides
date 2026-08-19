package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"fides/pkg/gitstatus"
)

type verifyBranchProtectionReq struct {
	TrailID  string `json:"trail_id"`
	Repo     string `json:"repo"`     // owner/repo (github) or group/project (gitlab)
	Branch   string `json:"branch"`   // default "main"
	Provider string `json:"provider"` // optional; default = the org's first git provider
}

// handleVerifyBranchProtection reads a branch's protection rules from the git
// provider and records a `branch-protection` attestation on the trail (compliant
// when the branch is protected and requires review). Turns the "protected
// branch" assertion into verified evidence.
func (s *Server) handleVerifyBranchProtection(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req verifyBranchProtectionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if req.TrailID == "" || req.Repo == "" {
		http.Error(w, "trail_id and repo are required", http.StatusBadRequest)
		return
	}
	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		http.Error(w, "invalid trail_id", http.StatusBadRequest)
		return
	}
	if !s.requireTrailInOrg(w, r, trailID) {
		return
	}
	branch := req.Branch
	if branch == "" {
		branch = "main"
	}

	providers, err := gitstatus.NewDBLoader(s.DB, s.Secrets).Providers(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	var cfg gitstatus.ProviderConfig
	found := false
	for _, p := range providers {
		if req.Provider == "" || p.Provider == req.Provider {
			cfg = p
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "no matching git provider configured for this org (see: fides git-provider)", http.StatusBadRequest)
		return
	}

	repo := gitstatus.Repo{Host: cfg.Host, Path: req.Repo}
	bp, err := gitstatus.GetBranchProtection(r.Context(), http.DefaultClient, cfg.Provider, cfg.APIBase, cfg.Token, repo, branch)
	if err != nil {
		internalError(w, err)
		return
	}
	// GitHub reports required reviews; require protected + >=1 review. GitLab's
	// review count isn't in this call, so protected is sufficient there.
	compliant := bp.Protected && (cfg.Provider != "github" || bp.RequiredReviews >= 1)

	payload, _ := json.Marshal(bp)
	contentHash, prevHash, err := s.attestationChain(r.Context(), trailID, "branch-protection", "branch-protection", string(payload), compliant)
	if err != nil {
		internalError(w, err)
		return
	}
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO attestations (id, trail_id, name, type_name, payload, is_compliant, content_hash, prev_hash, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`,
		uuid.New(), trailID, "branch-protection", "branch-protection", string(payload), compliant, contentHash, prevHash); err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"trail_id":          trailID,
		"branch_protection": bp,
		"compliant":         compliant,
	})
}
