package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminConsolePageServes(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleAdminConsolePage(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Fides Admin Console", "Slack", "Service Accounts", "/api/v1/tenant/slack", "/api/v1/metrics/dora"} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin page missing %q", want)
		}
	}
}

func TestAdminConsoleIsPublicPage(t *testing.T) {
	if !isPublicPath("/admin") {
		t.Fatalf("/admin page shell should be public (API calls are cookie-authed)")
	}
}
