package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// The legacy rescue route reflects attacker-controlled path segments into a
// Location header. The only thing standing between that and an open redirect
// is the url.Values escaping in handleLegacyEvidenceLink, so this drives the
// full mux (pattern matching + PathValue unescaping included) with every
// segment shape that could break out of a relative path: separators, query and
// fragment metacharacters, traversal, protocol-relative and absolute-URL
// prefixes, and a CRLF header-injection attempt.
func TestLegacyEvidenceLinkNeverRedirectsOffOrigin(t *testing.T) {
	h := (&Server{}).Routes()

	cases := []struct {
		name   string
		target string
	}{
		{"plain", "/flows/web-app/trails/0a1b2c3d?attestation_type=sbom-cyclonedx"},
		{"encoded slash", "/flows/a%2Fb/trails/c%2Fd"},
		{"encoded question mark", "/flows/a%3Fb/trails/c%3Fredirect=evil"},
		{"encoded hash", "/flows/a%23b/trails/c%23frag"},
		{"encoded backslash", "/flows/a%5Cb/trails/c%5C%5Cevil.com"},
		{"dot-dot segment", "/flows/../trails/x"},
		{"encoded dot-dot", "/flows/%2E%2E/trails/x"},
		{"protocol-relative prefix", "/flows/%2F%2Fevil.com/trails/x"},
		{"absolute url prefix", "/flows/https:%2F%2Fevil.com/trails/x"},
		{"crlf injection", "/flows/a%0D%0ASet-Cookie:pwn=1/trails/x"},
		{"hostile attestation_type", "/flows/f/trails/t?attestation_type=%2F%2Fevil.com%2F%3Fx%3D1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))

			loc := rec.Header().Get("Location")
			if rec.Code < 300 || rec.Code > 399 {
				t.Fatalf("expected a redirect, got HTTP %d", rec.Code)
			}
			if loc == "" {
				t.Fatal("redirect with no Location header")
			}
			// The property under test: wherever the mux sends this (the rescue
			// handler's 302, or ServeMux's own path-cleaning 301), the target
			// must be a same-origin relative path. A scheme, a host, or a
			// "//host" prefix would let a ServiceNow-stored link bounce a
			// browser to an attacker's origin.
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("Location %q does not parse: %v", loc, err)
			}
			if u.Scheme != "" || u.Host != "" {
				t.Fatalf("off-origin redirect: Location %q has scheme=%q host=%q", loc, u.Scheme, u.Host)
			}
			if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") {
				t.Fatalf("Location %q is not a same-origin absolute path", loc)
			}
			t.Logf("HTTP %d Location: %s", rec.Code, loc)
		})
	}
}

// The happy path of the rescue route: the exact URL shape ARC wrote into
// ServiceNow must land on the portal deep link with both segments and the
// attestation_type carried over — and nothing else from the query.
func TestLegacyEvidenceLinkRewrite(t *testing.T) {
	h := (&Server{}).Routes()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/flows/web-app/trails/0a1b2c3d?attestation_type=sbom-cyclonedx&utm_source=snow", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("HTTP %d, want 302", rec.Code)
	}
	want := "/flows/?attestation_type=sbom-cyclonedx&flow=web-app&trail=0a1b2c3d"
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location %q, want %q", got, want)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", cc)
	}
}

// evidenceLinkRequest drives handleEvidenceLink directly with an authenticated
// principal, the way it is reached behind authMiddleware.
func evidenceLinkRequest(s *Server, org uuid.UUID, flow, trail, rawQuery string) *httptest.ResponseRecorder {
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/flows/x/trails/y", nil).WithContext(ctx)
	r.URL.RawQuery = rawQuery
	r.SetPathValue("flow", flow)
	r.SetPathValue("trail", trail)
	rec := httptest.NewRecorder()
	s.handleEvidenceLink(rec, r)
	return rec
}

func TestEvidenceLinkResolves(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the evidence-link integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	orgA, orgB := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgA, "a-"+orgA.String()[:8])
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgB, "b-"+orgB.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB) })

	flowID := uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'web-app')`, flowID, orgA)

	// ARC names trails by commit SHA; sha1 is shared by two trails so the
	// git_commit fallback has a tie that only "newest first" resolves.
	sha1 := strings.Repeat("a", 40)
	older, newer, named := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,created_at) VALUES ($1,$2,'run-1',$3,$4)`,
		older, flowID, sha1, now.Add(-2*time.Hour))
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,created_at) VALUES ($1,$2,'run-2',$3,$4)`,
		newer, flowID, sha1, now.Add(-1*time.Hour))
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,created_at) VALUES ($1,$2,$3,$4,$5)`,
		named, flowID, sha1[:7], strings.Repeat("b", 40), now)

	s := &Server{DB: pool}

	assertRedirect := func(t *testing.T, rec *httptest.ResponseRecorder, wantFlow, wantTrail uuid.UUID) {
		t.Helper()
		if rec.Code != http.StatusFound {
			t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("Location: %v", err)
		}
		if loc.Path != "/flows/" {
			t.Fatalf("Location path %q, want /flows/", loc.Path)
		}
		q := loc.Query()
		if q.Get("flow") != wantFlow.String() || q.Get("trail") != wantTrail.String() {
			t.Fatalf("Location %q, want flow=%s trail=%s", loc, wantFlow, wantTrail)
		}
	}

	t.Run("by names", func(t *testing.T) {
		assertRedirect(t, evidenceLinkRequest(s, orgA, "web-app", "run-1", ""), flowID, older)
	})
	t.Run("by UUIDs", func(t *testing.T) {
		assertRedirect(t, evidenceLinkRequest(s, orgA, flowID.String(), older.String(), ""), flowID, older)
	})
	t.Run("name beats git_commit fallback", func(t *testing.T) {
		// sha1[:7] is a trail NAME and no trail's git_commit; the name match
		// must win regardless of the fallback.
		assertRedirect(t, evidenceLinkRequest(s, orgA, "web-app", sha1[:7], ""), flowID, named)
	})
	t.Run("git_commit fallback picks newest", func(t *testing.T) {
		assertRedirect(t, evidenceLinkRequest(s, orgA, "web-app", sha1, ""), flowID, newer)
	})
	t.Run("forwards only attestation_type", func(t *testing.T) {
		rec := evidenceLinkRequest(s, orgA, "web-app", "run-1", "attestation_type=sbom-cyclonedx&utm_source=snow")
		assertRedirect(t, rec, flowID, older)
		q, _ := url.Parse(rec.Header().Get("Location"))
		if got := q.Query().Get("attestation_type"); got != "sbom-cyclonedx" {
			t.Fatalf("attestation_type %q not forwarded", got)
		}
		if q.Query().Has("utm_source") {
			t.Fatalf("unexpected query parameter forwarded: %q", q)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("Cache-Control %q, want no-store", cc)
		}
	})

	// A trail that does not exist and a trail that belongs to another tenant
	// must be indistinguishable: both fall out of the same org-scoped query as
	// sql.ErrNoRows, so a caller cannot probe other tenants' flow or trail
	// names by comparing responses.
	t.Run("cross-tenant 404 identical to nonexistent 404", func(t *testing.T) {
		missing := evidenceLinkRequest(s, orgA, "web-app", "no-such-trail", "")
		crossTenant := evidenceLinkRequest(s, orgB, "web-app", "run-1", "")
		if missing.Code != http.StatusNotFound || crossTenant.Code != http.StatusNotFound {
			t.Fatalf("HTTP %d / %d, want 404 / 404", missing.Code, crossTenant.Code)
		}
		if missing.Body.String() != crossTenant.Body.String() {
			t.Fatalf("404 bodies differ: %q vs %q", missing.Body.String(), crossTenant.Body.String())
		}
		if missingCT, crossCT := missing.Header().Get("Content-Type"), crossTenant.Header().Get("Content-Type"); missingCT != crossCT {
			t.Fatalf("404 Content-Type differs: %q vs %q", missingCT, crossCT)
		}
	})
}
