package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRiskRegisterShapeAndConsistency(t *testing.T) {
	reg := loadRiskRegister()
	if len(reg.Risks) < 6 {
		t.Fatalf("risk register has %d risks, expected at least 6", len(reg.Risks))
	}
	keys := map[string]bool{}
	for _, r := range reg.Risks {
		if r.Key == "" || r.Title == "" || r.Description == "" {
			t.Errorf("risk missing key/title/description: %+v", r)
		}
		if keys[r.Key] {
			t.Errorf("duplicate risk key %s", r.Key)
		}
		keys[r.Key] = true
	}
	// Every risk key the catalog claims to mitigate MUST exist in the register,
	// or the derived control<->risk map has dangling links.
	for _, c := range parsedControlCatalog.Controls {
		for _, m := range c.Mitigates {
			if !keys[m] {
				t.Errorf("control %s mitigates %q which is not in the risk register", c.Code, m)
			}
		}
	}
}

func TestRiskRegisterHandlerDerivesControls(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/risk-register", nil)
	rec := httptest.NewRecorder()
	s.handleRiskRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rec.Code)
	}
	var out struct {
		Risks []struct {
			Key         string           `json:"key"`
			MitigatedBy []map[string]any `json:"mitigated_by"`
		} `json:"risks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, r := range out.Risks {
		if r.Key == "supply_chain_compromise" {
			found = true
			if len(r.MitigatedBy) == 0 {
				t.Errorf("supply_chain_compromise should have >=1 mitigating control derived from the catalog")
			}
		}
	}
	if !found {
		t.Error("supply_chain_compromise missing from register output")
	}
}
