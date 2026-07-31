package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSDLCPhasesCoverAllControls(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleSDLC(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sdlc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rec.Code)
	}
	var out struct {
		Phases []struct {
			Name     string           `json:"name"`
			Controls []map[string]any `json:"controls"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Phases) != 3 {
		t.Fatalf("expected 3 phases, got %d", len(out.Phases))
	}
	total := 0
	for _, p := range out.Phases {
		total += len(p.Controls)
	}
	// Every catalog control must land in exactly one phase (no drops/dupes).
	if total != len(parsedControlCatalog.Controls) {
		t.Fatalf("phases hold %d controls, catalog has %d — mapping drops or duplicates", total, len(parsedControlCatalog.Controls))
	}
}
