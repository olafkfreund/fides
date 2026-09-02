package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// The stable evidence URL. ARC's CI writes Fides evidence links into ServiceNow
// as permanent audit records (sn_devops_evidence_payload.payload_url, the CR's
// u_fides_trail_url), built as /flows/<flow>/trails/<commit-sha>. Fides never
// defined a deep-linkable evidence URL, so ARC guessed one — and it 404'd,
// because the portal is a static export with no dynamic routes. These two
// handlers make that URL shape real:
//
//   - handleEvidenceLink is the canonical, authenticated resolver under
//     /api/v1/. It turns a flow/trail given by name OR UUID into a 302 to the
//     portal's flows page, which deep-links via query parameters.
//   - handleLegacyEvidenceLink rescues the dead URLs already written into
//     ServiceNow, which are immutable and cannot be edited.
//
// Both redirect to /flows/, which is served from ./web -- the portal build that
// Dockerfile.server copies over that directory. The copy checked into git holds
// only the markdown docs, so running cmd/server straight from a checkout
// redirects into a 404 until `cd portal && npm run build` has run. Every
// shipped image has the real thing.

// handleEvidenceLink resolves GET /api/v1/evidence/flows/{flow}/trails/{trail}
// to the portal deep link /flows/?flow=<uuid>&trail=<uuid>.
//
// {flow} and {trail} each accept a name or a UUID: flows are UNIQUE(org_id,
// name) and trails UNIQUE(flow_id, name), so (org, flow, trail) names a single
// row. ARC names trails by commit SHA, so when neither the id nor the name
// matches, the newest trail whose git_commit matches is taken instead.
func (s *Server) handleEvidenceLink(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flow := r.PathValue("flow")
	trail := r.PathValue("trail")

	// One org-scoped query for every outcome. Comparing ids via ::text keeps a
	// non-UUID name from raising a Postgres cast error, and ranking id/name
	// matches above git_commit matches implements the SHA fallback without a
	// second round trip.
	var flowID, trailID uuid.UUID
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT f.id, t.id
		 FROM trails t JOIN flows f ON f.id = t.flow_id
		 WHERE f.org_id = $1
		   AND (f.id::text = $2 OR f.name = $2)
		   AND (t.id::text = $3 OR t.name = $3 OR t.git_commit = $3)
		 ORDER BY (t.id::text = $3 OR t.name = $3) DESC, t.created_at DESC
		 LIMIT 1`, orgID, flow, trail).Scan(&flowID, &trailID)
	if errors.Is(err, sql.ErrNoRows) {
		// "Does not exist" and "belongs to another tenant" both land here, off
		// the same org-scoped query. That is deliberate: a distinguishable
		// response would let an authenticated caller probe other tenants'
		// flow and trail names, so the two cases must stay byte-identical.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	q := url.Values{}
	q.Set("flow", flowID.String())
	q.Set("trail", trailID.String())
	// Forwarded, not validated: nothing server-side consumes attestation_type;
	// it only tells the portal which attestation to highlight.
	if at := r.URL.Query().Get("attestation_type"); at != "" {
		q.Set("attestation_type", at)
	}
	// Evidence links are opened from audit records long after the trail moved
	// or was renamed; a cached redirect would pin a stale resolution.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/flows/?"+q.Encode(), http.StatusFound)
}

// handleLegacyEvidenceLink serves GET /flows/{flow}/trails/{trail} — the URL
// shape ARC already wrote into ServiceNow before the canonical resolver
// existed. Those records are immutable audit evidence and cannot be edited, so
// the URL itself is made to resolve.
//
// This is a pure string rewrite: no database access, no auth, the same 302 for
// every input. That is what makes it safe to serve publicly — it reveals
// nothing the caller did not already send. The path segments are
// attacker-controlled, so both are put through url.Values encoding, which pins
// the Location to a same-origin relative path ("/flows/?...") no matter what
// the segments contain.
func handleLegacyEvidenceLink(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Set("flow", r.PathValue("flow"))
	q.Set("trail", r.PathValue("trail"))
	if at := r.URL.Query().Get("attestation_type"); at != "" {
		q.Set("attestation_type", at)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/flows/?"+q.Encode(), http.StatusFound)
}
