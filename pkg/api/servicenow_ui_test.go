package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceNowAdminPageServesHTML(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleServiceNowAdminPage(rec, httptest.NewRequest(http.MethodGet, "/servicenow", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected html content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ServiceNow Integration") || !strings.Contains(body, "/api/v1/tenant/servicenow") {
		t.Fatalf("page does not contain expected content")
	}
}

func TestServiceNowAdminPageIsPublic(t *testing.T) {
	// The page shell must be reachable without auth (its API calls carry the cookie).
	if !isPublicPath("/servicenow") {
		t.Fatalf("/servicenow page should be a public path")
	}
	// The events API must NOT be public.
	if isPublicPath("/api/v1/tenant/servicenow/events") {
		t.Fatalf("the events API must require auth")
	}
}
