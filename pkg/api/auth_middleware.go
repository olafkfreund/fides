package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	pathpkg "path"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/db"
)

// Authentication and request middleware.
//
// Split out of server.go, which had grown to 4,000 lines with the code that
// decides who a caller is sitting in the middle of it. This is the file to read
// -- and to test -- when the question is "how does a request get a tenant?".
//
// The Principal's OrgID is the ONLY source of tenant scoping downstream; no
// handler may take an org id from a request body or query (H2 / IDOR).

// limitBody wraps every request body in http.MaxBytesReader.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// isPublicPath reports whether a request path is reachable without authentication.
// Everything else under /api/v1 requires a valid bearer token.
func isPublicPath(path string) bool {
	publicExact := map[string]bool{
		"/healthz":                 true,
		"/metrics":                 true,
		"/api/v1/auth/login":       true,
		"/api/v1/auth/callback":    true,
		"/api/v1/auth/local-login": true,
		"/api/v1/swagger.json":     true,
		"/swagger":                 true,
		"/llms.txt":                true,
		"/llms-full.txt":           true,
		// K8s admission webhook: authenticated by the API server via mTLS, not a token.
		"/api/v1/admission/validate": true,
	}
	if publicExact[path] {
		return true
	}
	// Inbound webhooks authenticate via the provider's HMAC/token signature.
	if strings.HasPrefix(path, "/api/v1/webhooks/") {
		return true
	}
	// The static web portal and its assets are public; the API surface is not.
	//
	// Decided on the CLEANED path. Otherwise "/healthz/../api/v1/flows" does not
	// start with /api/v1/ and is classified public, and authentication ends up
	// relying on http.ServeMux redirecting the traversal away (it does -- 307 to
	// the cleaned path -- so this was not exploitable). Depending on the router
	// to keep the auth boundary honest is the wrong shape: this decides for
	// itself.
	return !strings.HasPrefix(pathpkg.Clean("/"+strings.TrimPrefix(path, "/")), "/api/v1/")
}

// authMiddleware authenticates the API surface and attaches a Principal to the
// request context. Two credential types are accepted:
//   - an interactive SSO session cookie (set by the OAuth callback), or
//   - the static service bearer token FIDES_API_TOKEN (used by the CLI/MCP),
//     whose tenant scope is fixed by FIDES_API_ORG_ID.
//
// The Principal's OrgID is the ONLY source of tenant scoping downstream; handlers
// must never trust an org_id from the request body or query (see H2 / IDOR).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		portalUser := os.Getenv("PORTAL_USERNAME")
		portalPass := os.Getenv("PORTAL_PASSWORD")

		// System paths bypass authentication
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" || r.URL.Path == "/swagger" || r.URL.Path == "/api/v1/swagger.json" || r.URL.Path == "/llms.txt" || r.URL.Path == "/llms-full.txt" {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Basic Auth check if portal credentials are set
		if portalUser != "" && portalPass != "" {
			username, password, ok := r.BasicAuth()
			if ok && constantTimeEquals(username, portalUser) && constantTimeEquals(password, portalPass) {
				orgID, configured := portalTenant()
				if !configured {
					http.Error(w, "portal tenant (FIDES_API_ORG_ID) is not configured", http.StatusServiceUnavailable)
					return
				}
				principal := s.resolvePortalPrincipal(r.Context(), orgID, username)
				s.serveAuthenticated(w, r, principal, next)
				return
			}
		}

		// 2. Standard public path bypass (static files and public auth routes)
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Interactive session cookie.
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if p, ok := s.Sessions.Get(c.Value, time.Now()); ok {
				s.serveAuthenticated(w, r, &p, next)
				return
			}
		}

		// 4. Static service bearer token.
		// The env service token gates whether API auth is configured at all.
		expected := os.Getenv("FIDES_API_TOKEN")
		if expected == "" {
			http.Error(w, "API authentication is not configured on the server", http.StatusServiceUnavailable)
			return
		}

		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		presented := strings.TrimPrefix(authz, prefix)

		// 1) Static env service token (constant-time compare; tenant from FIDES_API_ORG_ID).
		if subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1 {
			orgID, err := uuid.Parse(os.Getenv("FIDES_API_ORG_ID"))
			if err != nil {
				http.Error(w, "service token tenant (FIDES_API_ORG_ID) is not configured", http.StatusServiceUnavailable)
				return
			}
			s.serveAuthenticated(w, r, &auth.Principal{OrgID: orgID, Role: auth.RoleAdmin, Kind: "service"}, next)
			return
		}

		// 2) Per-tenant service-account API key.
		if p := s.authServiceAccountKey(r.Context(), presented); p != nil {
			s.serveAuthenticated(w, r, p, next)
			return
		}

		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	})
}

// serveAuthenticated attaches the principal to the request context and, when
// RLS scoping is enabled (FIDES_RLS_ENABLED=true), pins a tenant-scoped DB
// connection (app.current_org set to the principal's org) into the context so
// handlers' s.q(ctx) calls are isolated by Postgres RLS. The connection is
// released after the handler returns.
func (s *Server) serveAuthenticated(w http.ResponseWriter, r *http.Request, p *auth.Principal, next http.Handler) {
	ctx := auth.WithPrincipal(r.Context(), p)

	if db.RLSEnabled() && s.DB != nil {
		conn, release, err := db.ScopedConn(ctx, s.DB, p.OrgID.String())
		if err != nil {
			internalError(w, err)
			return
		}
		defer release()
		ctx = db.WithQuerier(ctx, conn)
	}

	next.ServeHTTP(w, r.WithContext(ctx))
}

// principalOrg returns the authenticated tenant for the request. Handlers use
// this as the sole source of org scoping. The bool is false only if the request
// somehow bypassed authMiddleware (defensive).
func principalOrg(r *http.Request) (uuid.UUID, bool) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		return uuid.UUID{}, false
	}
	return p.OrgID, true
}

// securityHeaders adds baseline hardening headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// DENY: the source-owned portal never frames itself, and the Go-served
		// admin pages that needed SAMEORIGIN framing (via web/admin-tab.js) were
		// removed after the portal cutover. Block all framing (clickjacking).
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
