package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlCatalogShape(t *testing.T) {
	cat := loadControlCatalog()
	if len(cat.Controls) < 10 {
		t.Fatalf("catalog has %d controls, expected at least 10", len(cat.Controls))
	}
	seen := map[string]bool{}
	for _, c := range cat.Controls {
		if c.Code == "" || c.Title == "" || c.Summary == "" {
			t.Errorf("control missing code/title/summary: %+v", c)
		}
		if c.Type != "preventive" && c.Type != "detective" {
			t.Errorf("%s: bad type %q", c.Code, c.Type)
		}
		if c.Area == "" {
			t.Errorf("%s: missing area", c.Code)
		}
		if len(c.Requirements) == 0 {
			t.Errorf("%s: no requirements", c.Code)
		}
		if len(c.FrameworkRefs) == 0 {
			t.Errorf("%s: no framework refs", c.Code)
		}
		for _, ref := range c.FrameworkRefs {
			if ref.Framework == "" || ref.Clause == "" || ref.Note == "" {
				t.Errorf("%s: framework ref missing field: %+v", c.Code, ref)
			}
		}
		if seen[c.Code] {
			t.Errorf("duplicate control code %s", c.Code)
		}
		seen[c.Code] = true
	}
}

func TestControlCatalogFilter(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-catalog?framework=SOC2", nil)
	rec := httptest.NewRecorder()
	s.handleControlCatalog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rec.Code)
	}
	var out controlCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Controls) == 0 {
		t.Fatal("SOC2 filter returned no controls")
	}
	for _, c := range out.Controls {
		ok := false
		for _, ref := range c.FrameworkRefs {
			if strings.EqualFold(ref.Framework, "SOC2") {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s returned by SOC2 filter but has no SOC2 ref", c.Code)
		}
	}
}
