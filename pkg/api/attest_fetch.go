package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"

	"fides/pkg/events"
	"fides/pkg/evidence"
	"fides/pkg/gitstatus"
)

// attestFetchReq requests ingestion of platform-native attestations
// (GitHub Artifact Attestations, GitLab Attestations) for a built artifact.
type attestFetchReq struct {
	TrailID        string `json:"trail_id"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Provider       string `json:"provider"` // github | gitlab; optional if it can be inferred from the trail's git host
	Repo           string `json:"repo"`     // owner/repo (github) or group/project (gitlab); defaults to the trail's recorded git repository
}

type attestFetchResult struct {
	PredicateType string `json:"predicate_type"`
	Compliant     bool   `json:"compliant"`
	SourceURL     string `json:"source_url"`
}

// handleAttestFetch fetches platform-native SLSA provenance/attestations for
// an artifact sha256 from the configured git provider (using its stored
// token), normalizes each into an evidence.Result, and records them as
// attestations on the trail's tamper-evidence chain -- federating
// GitHub/GitLab-native attestations into the Fides chain.
func (s *Server) handleAttestFetch(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req attestFetchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	trailID, err := uuid.Parse(req.TrailID)
	if err != nil {
		http.Error(w, "valid trail_id is required", http.StatusBadRequest)
		return
	}
	sha := strings.ToLower(strings.TrimSpace(req.ArtifactSHA256))
	if len(sha) != 64 {
		http.Error(w, "artifact_sha256 must be a 64-character hex digest", http.StatusBadRequest)
		return
	}
	if req.Provider != "" && req.Provider != gitstatus.ProviderGitHub && req.Provider != gitstatus.ProviderGitLab {
		http.Error(w, "provider must be github or gitlab", http.StatusBadRequest)
		return
	}

	loader := gitstatus.NewDBLoader(s.DB, s.Secrets)

	repoPath := req.Repo
	var host string
	if repoPath == "" {
		tg, err := loader.TrailGit(r.Context(), orgID, trailID)
		if err != nil {
			internalError(w, err)
			return
		}
		if tg.Repository == "" {
			http.Error(w, "trail has no recorded git repository; pass repo explicitly", http.StatusBadRequest)
			return
		}
		parsedRepo, err := gitstatus.ParseRepo(tg.Repository)
		if err != nil {
			badRequest(w, err)
			return
		}
		repoPath, host = parsedRepo.Path, parsedRepo.Host
	}

	providers, err := loader.Providers(r.Context(), orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	wantProvider := req.Provider
	if wantProvider == "" {
		// Infer the provider from whichever configured host matches the trail's repo.
		if cfg, ok := gitstatus.ResolveProvider(providers, gitstatus.ProviderGitHub, host); ok {
			wantProvider = cfg.Provider
		} else if cfg, ok := gitstatus.ResolveProvider(providers, gitstatus.ProviderGitLab, host); ok {
			wantProvider = cfg.Provider
		}
	}
	if wantProvider == "" {
		http.Error(w, "provider is required (no configured git provider matches the trail's git host)", http.StatusBadRequest)
		return
	}
	cfg, ok := gitstatus.ResolveProvider(providers, wantProvider, host)
	if !ok {
		http.Error(w, fmt.Sprintf("no enabled %s git-provider configuration found for this organization", wantProvider), http.StatusBadRequest)
		return
	}

	repo := gitstatus.Repo{Host: cfg.Host, Path: repoPath}
	statements, err := gitstatus.FetchAttestations(r.Context(), s.httpClient, cfg.Provider, cfg.APIBase, cfg.Token, repo, sha)
	if err != nil {
		internalError(w, err)
		return
	}
	if len(statements) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"recorded": 0, "compliant": false, "provider": cfg.Provider, "repo": repoPath,
			"message": "no platform-native attestations found for this artifact",
		})
		return
	}

	results := make([]attestFetchResult, 0, len(statements))
	allCompliant := true
	for i, stmt := range statements {
		result, err := evidence.NormalizeProvenance(stmt.Statement, sha)
		if err != nil {
			internalError(w, err)
			return
		}
		if !result.Compliant {
			allCompliant = false
		}
		payload, _ := json.Marshal(result)
		name := fmt.Sprintf("%s-provenance-%d", cfg.Provider, i+1)

		contentHash, prevHash, err := s.attestationChain(r.Context(), trailID, name, "provenance", string(payload), result.Compliant)
		if err != nil {
			internalError(w, err)
			return
		}
		_, err = s.q(r.Context()).ExecContext(r.Context(),
			`INSERT INTO attestations (id, trail_id, artifact_sha256, name, type_name, payload, is_compliant, content_hash, prev_hash, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())`,
			uuid.New(), trailID, sha, name, "provenance", string(payload), result.Compliant, contentHash, prevHash)
		if err != nil {
			internalError(w, err)
			return
		}
		results = append(results, attestFetchResult{PredicateType: stmt.PredicateType, Compliant: result.Compliant, SourceURL: stmt.SourceURL})
	}

	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		_ = events.Enqueue(r.Context(), s.q(r.Context()), orgID, "compliance.evaluated", map[string]any{
			"trail_id": trailID.String(), "attestation": "provenance", "compliant": allCompliant,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"recorded":     len(results),
		"compliant":    allCompliant,
		"provider":     cfg.Provider,
		"repo":         repoPath,
		"attestations": results,
	})
}
