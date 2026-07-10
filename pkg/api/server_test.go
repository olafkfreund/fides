package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestSaveUserRequiresAdmin asserts the identity-registration endpoint is
// admin-only: a non-Admin principal is rejected with 403 before any DB write,
// so a Writer cannot seed on_behalf_of-eligible identities for SoD approvals.
func TestSaveUserRequiresAdmin(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenant/users",
		strings.NewReader(`{"name":"X","email":"x@example.com","role":"Writer"}`))
	req = req.WithContext(auth.WithPrincipal(context.Background(),
		&auth.Principal{OrgID: uuid.New(), Role: auth.RoleWriter, Kind: "session"}))
	rec := httptest.NewRecorder()
	s.handleSaveUser(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin handleSaveUser = %d, want 403; body=%s", rec.Code, rec.Body.String())
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

func TestLocalLoginFlow(t *testing.T) {
	// 1. Without credentials configured -> returns 403 Forbidden
	t.Setenv("PORTAL_USERNAME", "")
	t.Setenv("PORTAL_PASSWORD", "")
	s := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local-login", strings.NewReader(`{"username":"admin","password":"password"}`))
	rec := httptest.NewRecorder()
	s.handleLocalLogin(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	// 2. With credentials configured, bad password -> returns 401 Unauthorized
	t.Setenv("PORTAL_USERNAME", "admin")
	t.Setenv("PORTAL_PASSWORD", "secret")

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/local-login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	rec = httptest.NewRecorder()
	s.handleLocalLogin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// 3. Correct credentials -> returns 200 and sets cookie.
	// The portal tenant must be configured (no hardcoded default org — H2).
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/local-login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	rec = httptest.NewRecorder()
	s.handleLocalLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected session cookie in response")
	}

	// Verify the session is in the store
	principal, ok := s.Sessions.Get(sessionCookie.Value, time.Now())
	if !ok {
		t.Fatalf("session not found in store")
	}
	if principal.Email != "admin" {
		t.Fatalf("expected session email 'admin', got '%s'", principal.Email)
	}
}
