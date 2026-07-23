package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"fides/pkg/ledger"
	"fides/pkg/tsa"
)

// chainVerifyResp is the verify-chain response: the ledger verdict plus, if the
// trail has been externally anchored, the RFC3161 timestamp status.
type chainVerifyResp struct {
	ledger.Verdict
	ExternalAnchor *externalAnchorInfo `json:"external_anchor,omitempty"`
}

type externalAnchorInfo struct {
	Anchored    bool      `json:"anchored"`
	HeadMatches bool      `json:"head_matches"`
	TSAURL      string    `json:"tsa_url,omitempty"`
	AnchoredAt  time.Time `json:"anchored_at,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"` // TSA-asserted time the head existed
	Error       string    `json:"error,omitempty"`
}

// trailChainHead returns a trail's current chain head (the most recent
// attestation content_hash), or "" if the trail has no chained attestations.
func (s *Server) trailChainHead(ctx context.Context, trailID uuid.UUID) (string, error) {
	var head string
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT COALESCE(content_hash, '') FROM attestations
		 WHERE trail_id = $1 AND content_hash IS NOT NULL
		 ORDER BY created_at DESC, id DESC LIMIT 1`, trailID).Scan(&head)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return head, err
}

// externalAnchorStatus loads a trail's most recent external anchor (if any) and
// verifies the stored RFC3161 token, reporting whether the anchored head still
// equals the current chain head. Returns nil when the trail was never anchored.
func (s *Server) externalAnchorStatus(ctx context.Context, trailID uuid.UUID, currentHead string) *externalAnchorInfo {
	var anchoredHead, tsaURL string
	var token []byte
	var anchoredAt time.Time
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT chain_head_hash, tsa_url, timestamp_token, anchored_at
		 FROM trail_anchors WHERE trail_id = $1 ORDER BY anchored_at DESC LIMIT 1`, trailID).
		Scan(&anchoredHead, &tsaURL, &token, &anchoredAt)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return &externalAnchorInfo{Error: "failed to load anchor"}
	}
	info := &externalAnchorInfo{Anchored: true, TSAURL: tsaURL, AnchoredAt: anchoredAt}
	t, verr := tsa.VerifyToken(token, anchoredHead)
	if verr != nil {
		info.Error = verr.Error()
		return info
	}
	info.Timestamp = t
	// The token proves the anchored head existed at time t; head_matches reports
	// whether the current chain head is still that anchored head (a tampered or
	// extended chain will differ).
	info.HeadMatches = anchoredHead != "" && anchoredHead == currentHead
	return info
}

// handleCreateTrailAnchor timestamps a trail's current chain head with an
// external RFC3161 TSA and stores the token. The TSA URL comes from the request
// body (tsa_url) or the FIDES_TSA_URL env var. Admin-scoped.
func (s *Server) handleCreateTrailAnchor(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}
	var req struct {
		TSAURL string `json:"tsa_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	tsaURL := req.TSAURL
	if tsaURL == "" {
		tsaURL = os.Getenv("FIDES_TSA_URL")
	}
	if tsaURL == "" {
		http.Error(w, "no TSA configured: set tsa_url or FIDES_TSA_URL", http.StatusBadRequest)
		return
	}

	head, err := s.trailChainHead(r.Context(), trailID)
	if err != nil {
		internalError(w, err)
		return
	}
	if head == "" {
		http.Error(w, "trail has no chained attestations to anchor", http.StatusBadRequest)
		return
	}

	token, err := tsa.RequestToken(r.Context(), tsaURL, head)
	if err != nil {
		log.Printf("tsa anchor failed for trail %s: %v", trailID, err)
		http.Error(w, "timestamp authority error: "+err.Error(), http.StatusBadGateway)
		return
	}

	id := uuid.New()
	anchoredAt := time.Now()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO trail_anchors (id, org_id, trail_id, chain_head_hash, tsa_url, timestamp_token, anchored_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, p.OrgID, trailID, head, tsaURL, token, anchoredAt); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"id": id, "trail_id": trailID, "chain_head_hash": head,
		"tsa_url": tsaURL, "anchored_at": anchoredAt,
	})
}
