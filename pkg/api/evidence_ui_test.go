package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvidenceVaultPageServesHTML(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleEvidenceVaultPage(rec, httptest.NewRequest(http.MethodGet, "/evidence", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected html content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Evidence Vault") || !strings.Contains(body, "/api/v1/trails/") {
		t.Fatalf("page does not contain expected content")
	}
}

func TestEvidenceVaultPageIsPublic(t *testing.T) {
	// The page shell must be reachable without auth (its API calls carry the cookie).
	if !isPublicPath("/evidence") {
		t.Fatalf("/evidence page should be a public path")
	}
	// The underlying data APIs it calls must NOT be public.
	for _, p := range []string{
		"/api/v1/flows",
		"/api/v1/search/attestations",
	} {
		if isPublicPath(p) {
			t.Fatalf("%s must require auth", p)
		}
	}
}
