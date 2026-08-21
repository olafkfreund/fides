package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"fides/pkg/auth"
)

// The middleware decides who a caller is, and therefore whose data they see.
// These tests are about the paths that must REFUSE. The accept paths already
// have coverage from the handler tests; a wrongly-refused request is a bug
// report, whereas a wrongly-accepted one is an incident nobody files.

// probe records whether the request reached the handler behind the middleware,
// and with which tenant.
type probe struct {
	reached bool
	org     string
}

func (p *probe) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.reached = true
		if pr, ok := auth.FromContext(r.Context()); ok {
			p.org = pr.OrgID.String()
		}
		w.WriteHeader(http.StatusOK)
	})
}

func serveThrough(t *testing.T, s *Server, req *http.Request) (*httptest.ResponseRecorder, *probe) {
	t.Helper()
	p := &probe{}
	rec := httptest.NewRecorder()
	s.authMiddleware(p.handler()).ServeHTTP(rec, req)
	return rec, p
}

func TestAuthMiddlewareRejectsMissingCredentials(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "a-service-token")
	t.Setenv("FIDES_API_ORG_ID", "6f1a2f4e-0000-4000-8000-000000000001")
	s := &Server{}

	rec, p := serveThrough(t, s, httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: want 401, got %d", rec.Code)
	}
	if p.reached {
		t.Fatal("an unauthenticated request reached the handler")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("want a Bearer challenge, got %q", got)
	}
}

func TestAuthMiddlewareRejectsWrongBearerToken(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "the-real-token")
	t.Setenv("FIDES_API_ORG_ID", "6f1a2f4e-0000-4000-8000-000000000001")
	s := &Server{}

	for _, presented := range []string{
		"not-the-token",
		"the-real-toke",   // one char short
		"the-real-tokenX", // one char long
		"",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
		req.Header.Set("Authorization", "Bearer "+presented)
		rec, p := serveThrough(t, s, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: want 401, got %d", presented, rec.Code)
		}
		if p.reached {
			t.Errorf("token %q reached the handler", presented)
		}
	}
}

// A token in the right place but the wrong scheme is not a credential.
func TestAuthMiddlewareRejectsNonBearerScheme(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "the-real-token")
	t.Setenv("FIDES_API_ORG_ID", "6f1a2f4e-0000-4000-8000-000000000001")
	s := &Server{}

	for _, header := range []string{
		"the-real-token",        // no scheme
		"Token the-real-token",  // wrong scheme
		"bearer the-real-token", // Bearer is case-sensitive here
		"Basic the-real-token",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
		req.Header.Set("Authorization", header)
		rec, _ := serveThrough(t, s, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: want 401, got %d", header, rec.Code)
		}
	}
}

// Refusing to serve beats serving the wrong tenant. With no FIDES_API_TOKEN the
// server cannot authenticate anyone, and says so rather than letting a request
// through unauthenticated.
func TestAuthMiddlewareRefusesWhenNoAPITokenConfigured(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "")
	t.Setenv("PORTAL_USERNAME", "")
	t.Setenv("PORTAL_PASSWORD", "")
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec, p := serveThrough(t, s, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when auth is unconfigured, got %d", rec.Code)
	}
	if p.reached {
		t.Fatal("request served while authentication was not configured")
	}
}

// A valid service token with no tenant configured must not fall back to some
// default organisation. There is no safe default for "whose data is this".
func TestAuthMiddlewareRefusesValidTokenWithUnconfiguredTenant(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "the-real-token")
	t.Setenv("FIDES_API_ORG_ID", "") // not a UUID
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.Header.Set("Authorization", "Bearer the-real-token")
	rec, p := serveThrough(t, s, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when the service-token tenant is unset, got %d", rec.Code)
	}
	if p.reached {
		t.Fatal("a request was served with no tenant to scope it to")
	}
}

func TestAuthMiddlewareRejectsWrongBasicAuth(t *testing.T) {
	t.Setenv("PORTAL_USERNAME", "admin")
	t.Setenv("PORTAL_PASSWORD", "correct-horse")
	t.Setenv("FIDES_API_TOKEN", "the-real-token")
	t.Setenv("FIDES_API_ORG_ID", "6f1a2f4e-0000-4000-8000-000000000001")
	s := &Server{}

	for _, cred := range []string{"admin:wrong", "wrong:correct-horse", "wrong:wrong", ":"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
		rec, p := serveThrough(t, s, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%q: want 401, got %d", cred, rec.Code)
		}
		if p.reached {
			t.Errorf("%q reached the handler", cred)
		}
	}
}

// The bypass list is a security boundary: anything on it is reachable with no
// credentials at all, so it must not grow by accident.
func TestUnauthenticatedBypassIsLimitedToKnownPaths(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "the-real-token")
	t.Setenv("FIDES_API_ORG_ID", "6f1a2f4e-0000-4000-8000-000000000001")
	s := &Server{}

	// Health and discovery only. If a path is added here, it is deliberate.
	allowed := []string{"/healthz", "/metrics", "/swagger", "/api/v1/swagger.json", "/llms.txt", "/llms-full.txt"}
	for _, p := range allowed {
		rec, pr := serveThrough(t, s, httptest.NewRequest(http.MethodGet, p, nil))
		if !pr.reached || rec.Code != http.StatusOK {
			t.Errorf("%s should bypass auth, got %d", p, rec.Code)
		}
	}

	// Anything that reads tenant data must not.
	for _, p := range []string{
		"/api/v1/flows", "/api/v1/controls", "/api/v1/environments",
		"/api/v1/attestations", "/api/v1/controls/coverage",
		"/healthz/../api/v1/flows",
	} {
		rec, pr := serveThrough(t, s, httptest.NewRequest(http.MethodGet, p, nil))
		if pr.reached {
			t.Errorf("%s was served without credentials (code %d)", p, rec.Code)
		}
	}
}
