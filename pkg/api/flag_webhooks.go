package api

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// handleFlagWebhook ingests a feature-flag provider's outbound webhook (Unleash
// or Flagsmith), normalizes it to a flag change, and records it as a flag.changed
// attestation — the same path as POST /api/v1/flags/changed (#290). The webhook
// is authenticated by the normal Fides auth: configure the provider to send a
// Fides service-account key as its Authorization header.
// POST /api/v1/flags/webhook/{provider}
func (s *Server) handleFlagWebhook(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	provider := strings.ToLower(r.PathValue("provider"))
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		badRequest(w, err)
		return
	}

	var req flagChangedReq
	var parsed bool
	switch provider {
	case "unleash":
		req, parsed = parseUnleashWebhook(body)
	case "flagsmith":
		req, parsed = parseFlagsmithWebhook(body)
	default:
		http.Error(w, "unsupported flag provider (want unleash|flagsmith)", http.StatusBadRequest)
		return
	}
	if !parsed || strings.TrimSpace(req.FlagKey) == "" {
		http.Error(w, "could not extract a flag change from the "+provider+" payload", http.StatusBadRequest)
		return
	}
	req.Source = provider

	flowID, err := s.resolveFlagFlow(r.Context(), orgID, "")
	if err != nil {
		internalError(w, err)
		return
	}
	trailID, attID, err := s.writeFlagChange(r.Context(), orgID, flowID, req)
	if err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"trail_id": trailID, "attestation_id": attID, "flag_key": req.FlagKey, "provider": provider})
}

// parseUnleashWebhook maps an Unleash addon webhook event to a flag change.
// Unleash sends the actor as createdBy and the flag as featureName; the new
// state is derived from the event type (…enabled / …disabled).
func parseUnleashWebhook(body []byte) (flagChangedReq, bool) {
	var e struct {
		Type        string `json:"type"`
		CreatedBy   string `json:"createdBy"`
		FeatureName string `json:"featureName"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.FeatureName == "" {
		return flagChangedReq{}, false
	}
	req := flagChangedReq{FlagKey: e.FeatureName, Environment: e.Environment, Actor: e.CreatedBy}
	switch {
	case strings.Contains(e.Type, "enabled"):
		req.NewState = "on"
	case strings.Contains(e.Type, "disabled"):
		req.NewState = "off"
	default:
		req.NewState = "updated"
	}
	return req, true
}

// flagsmithFeatureRe extracts a quoted feature name from a Flagsmith audit log
// message, e.g. "Flag state updated for feature 'checkout_v2'".
var flagsmithFeatureRe = regexp.MustCompile(`'([^']+)'`)

// parseFlagsmithWebhook maps a Flagsmith audit-log webhook to a flag change. The
// feature name is embedded in the free-text log; the actor and environment come
// from structured fields.
func parseFlagsmithWebhook(body []byte) (flagChangedReq, bool) {
	var e struct {
		Data struct {
			Log    string `json:"log"`
			Author struct {
				Email string `json:"email"`
			} `json:"author"`
			Environment struct {
				Name string `json:"name"`
			} `json:"environment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return flagChangedReq{}, false
	}
	flagKey := ""
	if m := flagsmithFeatureRe.FindStringSubmatch(e.Data.Log); len(m) == 2 {
		flagKey = m[1]
	}
	if flagKey == "" {
		return flagChangedReq{}, false
	}
	return flagChangedReq{
		FlagKey:     flagKey,
		Environment: e.Data.Environment.Name,
		Actor:       e.Data.Author.Email,
		NewState:    "updated",
	}, true
}
