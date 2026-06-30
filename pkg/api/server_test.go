package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fides/pkg/auth"

	"github.com/google/uuid"
)

// newTestServer builds a Server with just the in-memory stores needed by the
// auth middleware (no DB required for these tests).
func newTestServer() *Server {
	return &Server{
		States:   auth.NewStateStore(),
		Sessions: auth.NewSessionStore(),
	}
}

// echoOrg is a protected handler that writes the authenticated org id, proving
// the principal made it into the request context.
func echoOrg(w http.ResponseWriter, r *http.Request) {
	org, ok := principalOrg(r)
	if !ok {
		http.Error(w, "no principal", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(org.String()))
}

func TestAuthMiddlewareRejectsUnauthenticated(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "secret-token")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	s := newTestServer()
	h := s.authMiddleware(http.HandlerFunc(echoOrg))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddlewareFailsClosedWithoutToken(t *testing.T) {
	// No FIDES_API_TOKEN configured -> protected routes must not be served.
	t.Setenv("FIDES_API_TOKEN", "")

	s := newTestServer()
	h := s.authMiddleware(http.HandlerFunc(echoOrg))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 fail-closed, got %d", rec.Code)
	}
}

func TestAuthMiddlewareServiceToken(t *testing.T) {
	org := uuid.New()
	t.Setenv("FIDES_API_TOKEN", "secret-token")
	t.Setenv("FIDES_API_ORG_ID", org.String())

	s := newTestServer()
	h := s.authMiddleware(http.HandlerFunc(echoOrg))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != org.String() {
		t.Fatalf("service principal org mismatch: got %s want %s", rec.Body.String(), org)
	}
}

func TestAuthMiddlewareWrongTokenRejected(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "secret-token")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	s := newTestServer()
	h := s.authMiddleware(http.HandlerFunc(echoOrg))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", rec.Code)
	}
}

func TestAuthMiddlewareSessionCookieScopesTenant(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "secret-token")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	s := newTestServer()
	sessionOrg := uuid.New()
	token, err := s.Sessions.Create(auth.Principal{OrgID: sessionOrg, Role: auth.RoleViewer, Kind: "session"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	h := s.authMiddleware(http.HandlerFunc(echoOrg))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// The session's org must win — not the service token's org.
	if rec.Body.String() != sessionOrg.String() {
		t.Fatalf("session principal org mismatch: got %s want %s", rec.Body.String(), sessionOrg)
	}
}

func TestPublicPathsBypassAuth(t *testing.T) {
	for _, p := range []string{"/healthz", "/swagger", "/", "/index.html"} {
		if !isPublicPath(p) {
			t.Errorf("expected %s to be public", p)
		}
	}
	for _, p := range []string{"/api/v1/flows", "/api/v1/tenant/users"} {
		if isPublicPath(p) {
			t.Errorf("expected %s to be protected", p)
		}
	}
}
