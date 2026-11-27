package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/admission"
	"fides/pkg/auth"
	"fides/pkg/db"
	"fides/pkg/policy"
	"fides/pkg/vault"
)

const fixtureBearer = "route-test-static-token"
const fixturePassword = "auth-fixture-local-password"

type routeCredential func(*http.Request)

func routeBearer(token string) routeCredential {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func routeCookie(cookie *http.Cookie) routeCredential {
	return func(r *http.Request) { r.AddCookie(cookie) }
}

func routeSession(t *testing.T, srv *Server, org, role string, ttl time.Duration) routeCredential {
	t.Helper()
	token, err := srv.Sessions.Create(auth.Principal{
		OrgID: uuid.MustParse(org), Kind: "session", Role: role, Email: strings.ToLower(role) + "@example.invalid",
	}, ttl, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return routeCookie(&http.Cookie{Name: sessionCookieName, Value: token})
}

type routeAuthFixture struct {
	pool     *sql.DB
	server   *Server
	handler  http.Handler
	rowsSQL  string
	own      map[string]string
	other    map[string]string
	sessions map[string]routeCredential
}

func newRouteAuthFixture(t *testing.T) *routeAuthFixture {
	t.Helper()
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run routed authorization checks")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	schema := "auth_routes_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	mustExec(t, base, "CREATE SCHEMA "+pq.QuoteIdentifier(schema))
	t.Cleanup(func() {
		if _, err := base.Exec("DROP SCHEMA " + pq.QuoteIdentifier(schema) + " CASCADE"); err != nil {
			t.Errorf("drop authorization fixture schema: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema+",public")
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema + ",public"
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	own := seedMutationTenant(t, pool, "own")
	other := seedMutationTenant(t, pool, "other")
	t.Setenv("FIDES_API_TOKEN", fixtureBearer)
	t.Setenv("FIDES_API_ORG_ID", own["org"])
	t.Setenv("PORTAL_USERNAME", "")
	t.Setenv("PORTAL_PASSWORD", "")
	t.Setenv("FIDES_RLS_ENABLED", "false")
	t.Setenv("FIDES_EVENTS_ENABLED", "false")
	t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "false")
	t.Setenv("FIDES_TSA_URL", "")
	t.Setenv("FIDES_TSA_URLS", "")
	srv := &Server{
		DB: pool, Sessions: auth.NewSessionStore(), States: auth.NewStateStore(),
		Secrets: vault.NewEnvSecretsProvider(), PolicyEngine: policy.NewPolicyEngine(),
	}

	// Hash all tables in the private schema. Including xmin detects a committed
	// UPDATE that writes an existing value as well as changed row contents.
	rows, err := pool.Query(`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, fmt.Sprintf(
			`SELECT %s AS name, COALESCE(md5(string_agg(j, '' ORDER BY j)), '') AS digest
			FROM (SELECT to_jsonb(t)::text || t.xmin::text AS j FROM %s t) data`,
			pq.QuoteLiteral(name), pq.QuoteIdentifier(name)))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	f := &routeAuthFixture{
		pool: pool, server: srv, handler: srv.Routes(), rowsSQL: strings.Join(parts, " UNION ALL "),
		own: own, other: other, sessions: make(map[string]routeCredential),
	}
	for _, role := range []string{auth.RoleAdmin, auth.RoleWriter, auth.RoleAuditor, auth.RoleViewer} {
		f.sessions[role] = routeSession(t, srv, own["org"], role, time.Hour)
	}
	return f
}

func seedMutationTenant(t *testing.T, pool *sql.DB, label string) map[string]string {
	t.Helper()
	ids := make(map[string]string)
	for _, name := range []string{"org", "flow", "trail", "env", "control", "exception", "logical", "removeMember", "envPolicy", "policy", "user", "account", "key", "approve", "reject", "apply"} {
		ids[name] = uuid.NewString()
	}
	ids["sha"] = randSHA256()
	ids["removeSHA"] = randSHA256()
	insert := func(query string, values ...string) {
		t.Helper()
		args := make([]any, len(values))
		for i, key := range values {
			args[i] = ids[key]
		}
		mustExec(t, pool, query, args...)
	}
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, ids["org"], label)
	insert(`INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'seed flow')`, "flow", "org")
	insert(`INSERT INTO trails (id,flow_id,name,git_repository,git_commit) VALUES ($1,$2,'seed trail','https://git.example.invalid/fixture/project','0123456789abcdef')`, "trail", "flow")
	insert(`INSERT INTO attestations (trail_id,name,type_name,payload) VALUES ($1,'seed evidence','fixture','{}')`, "trail")
	insert(`INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'seed environment','k8s')`, "env", "org")
	insert(`INSERT INTO environment_snapshots (environment_id,created_at) VALUES ($1,now()-interval '2 minutes'),($1,now()-interval '1 minute')`, "env")
	// A real server row makes ownership denial distinguishable from a missing
	// config. The unsupported transport stops before any dispatch.
	insert(`INSERT INTO environment_mcp_servers (environment_id,name,transport)
		VALUES ($1,'inactive','sse')`, "env")
	insert(`INSERT INTO controls (id,org_id,key,name,required_types) VALUES ($1,$2,'fixture','Seed control',ARRAY['fixture'])`, "control", "org")
	insert(`INSERT INTO control_exceptions (id,org_id,control_key,reason,expires_at) VALUES ($1,$2,'fixture','seed waiver',now()+interval '1 day')`, "exception", "org")
	insert(`INSERT INTO logical_environments (id,org_id,name) VALUES ($1,$3,'seed logical'),($2,$3,'seed remove')`, "logical", "removeMember", "org")
	insert(`INSERT INTO logical_environment_members (logical_id,environment_id) VALUES ($1,$2)`, "removeMember", "env")
	insert(`INSERT INTO environment_policies (id,environment_id,name,required_types) VALUES ($1,$2,'seed policy',ARRAY['fixture'])`, "envPolicy", "env")
	insert(`INSERT INTO policies (id,org_id,name,rules) VALUES ($1,$2,'seed global policy','{}')`, "policy", "org")
	mustExec(t, pool, `INSERT INTO users (id,org_id,name,email,role) VALUES ($1,$2,'Fixture user',$3,'Writer')`,
		ids["user"], ids["org"], label+"@example.invalid")
	insert(`INSERT INTO service_accounts (id,org_id,name,role) VALUES ($1,$2,'seed account','Writer')`, "account", "org")
	mustExec(t, pool, `INSERT INTO service_account_keys (id,service_account_id,prefix,key_hash) VALUES ($1,$2,$3,'unused')`,
		ids["key"], ids["account"], label)
	insert(`INSERT INTO environment_allowlist (environment_id,artifact_sha256,reason) VALUES ($1,$2,'seed approval')`, "env", "removeSHA")
	insert(`INSERT INTO remediation_actions (id,org_id,environment_id,domain,proposed_by,status,params)
		VALUES ($1,$4,$5,'env_tag','proposer@example.invalid','proposed','{"tags":{"remediation":"fixture"}}'),
		       ($2,$4,$5,'env_tag','proposer@example.invalid','proposed','{"tags":{"remediation":"fixture"}}'),
		       ($3,$4,$5,'env_tag','proposer@example.invalid','approved','{"tags":{"remediation":"fixture"}}')`,
		"approve", "reject", "apply", "org", "env")
	return ids
}

func (f *routeAuthFixture) snapshot(t *testing.T) map[string]string {
	t.Helper()
	rows, err := f.pool.Query(f.rowsSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	state := make(map[string]string)
	for rows.Next() {
		var name, digest string
		if err := rows.Scan(&name, &digest); err != nil {
			t.Fatal(err)
		}
		state[name] = digest
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return state
}

func changedRouteTables(before, after map[string]string) []string {
	var changed []string
	for name, digest := range before {
		if after[name] != digest {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}

func serveMutation(t *testing.T, handler http.Handler, pattern, body string, credential routeCredential, want int, wantText string) *httptest.ResponseRecorder {
	t.Helper()
	method, target, _ := strings.Cut(pattern, " ")
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != nil {
		credential(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want || (wantText != "" && strings.TrimSpace(rec.Body.String()) != wantText) {
		t.Errorf("%s: expected HTTP %d %q, got %d %s", pattern, want, wantText, rec.Code, rec.Body)
	}
	return rec
}

func (f *routeAuthFixture) denied(t *testing.T, path, body string, credential routeCredential, status int, message string) {
	t.Helper()
	before := f.snapshot(t)
	rec := serveMutation(t, f.handler, path, body, credential, status, message)
	if len(rec.Result().Cookies()) != 0 {
		t.Error("denied response set a cookie")
	}
	if changed := changedRouteTables(before, f.snapshot(t)); len(changed) > 0 {
		t.Errorf("denied request wrote to %v", changed)
	}
}

func newMutationRouteFixture(t *testing.T, route mutationRoute) (*routeAuthFixture, string, string) {
	t.Helper()
	f := newRouteAuthFixture(t)
	ids := f.own
	switch route.pattern {
	case "POST /api/v1/attest/fetch":
		mustExec(t, f.pool, `INSERT INTO artifacts (sha256, org_id, trail_id, name, type)
			VALUES ($1, $2, $3, 'fixture', 'docker')`, ids["sha"], ids["org"], ids["trail"])
		f.stubGitProvider(t)
	case "POST /api/v1/verify-branch-protection":
		f.stubGitProvider(t)
	case "POST /api/v1/controls/{id}/unarchive":
		mustExec(t, f.pool, `UPDATE controls SET archived = true WHERE id = $1`, ids["control"])
	case "POST /api/v1/environments/{id}/unarchive":
		mustExec(t, f.pool, `UPDATE environments SET archived = true WHERE id = $1`, ids["env"])
	}

	provider := "unleash"
	if !strings.Contains(route.pattern, "/flags/") {
		provider = "github"
	}
	target := strings.NewReplacer(
		"{id}", ids[route.id], "{key}", "fixture", "{envId}", ids["env"],
		"{policyId}", ids["envPolicy"], "{sha}", ids["removeSHA"],
		"{keyId}", ids["key"], "{provider}", provider,
	).Replace(route.pattern)
	body := os.Expand(route.body, func(key string) string {
		id, ok := ids[key]
		if !ok {
			t.Fatalf("unknown route fixture $%s", key)
		}
		return id
	})
	return f, target, body
}

func (f *routeAuthFixture) admitted(t *testing.T, route mutationRoute, target, body, role string) {
	t.Helper()
	t.Run(role+"-admitted", func(t *testing.T) {
		before := f.snapshot(t)
		table, message := route.check, ""
		if route.status >= 400 {
			table, message = "", route.check
		}
		serveMutation(t, f.handler, target, body, f.sessions[role], route.status, message)
		after := f.snapshot(t)
		if table == "" {
			if changed := changedRouteTables(before, after); len(changed) > 0 {
				t.Errorf("expected no writes, changed %v", changed)
			}
		} else if before[table] == after[table] {
			t.Errorf("expected a write to %s", table)
		}
	})
}

func TestMutationAuthorizationIntegration(t *testing.T) {
	for _, route := range mutationRoutes {
		switch route.auth {
		case signedCallback, localLogin, admissionTLS, ssoState:
			continue // Exercised by TestPublicMutationAuthorizationIntegration.
		}
		t.Run(route.pattern, func(t *testing.T) {
			f, target, body := newMutationRouteFixture(t, route)
			t.Run("anonymous", func(t *testing.T) {
				f.denied(t, target, body, nil, http.StatusUnauthorized, "authentication required")
			})
			if route.auth == adminOnly || route.auth == writerOnly {
				deniedRoles := []string{auth.RoleViewer, auth.RoleAuditor}
				if route.auth == adminOnly {
					deniedRoles = append(deniedRoles, auth.RoleWriter)
				}
				for _, role := range deniedRoles {
					t.Run(role, func(t *testing.T) {
						f.denied(t, target, body, f.sessions[role], http.StatusForbidden, "")
					})
				}
			}
			if route.foreign {
				t.Run("other-tenant", func(t *testing.T) {
					if route.pattern == "POST /api/v1/trails/{id}/anchor" {
						// Resolve selects the configured string without dialing.
						t.Setenv("FIDES_TSA_URL", "https://tsa.example.invalid")
					}
					foreign := routeSession(t, f.server, f.other["org"], auth.RoleAdmin, time.Hour)
					f.denied(t, target, body, foreign, http.StatusNotFound, "")
				})
			}

			switch route.auth {
			case adminOnly:
				f.admitted(t, route, target, body, auth.RoleAdmin)
			case writerOnly:
				f.admitted(t, route, target, body, auth.RoleWriter)
				t.Run(auth.RoleAdmin+"-admission", func(t *testing.T) {
					adminFixture, adminTarget, adminBody := newMutationRouteFixture(t, route)
					adminFixture.admitted(t, route, adminTarget, adminBody, auth.RoleAdmin)
				})
			case authenticated:
				for _, role := range []string{auth.RoleViewer, auth.RoleAuditor, auth.RoleWriter, auth.RoleAdmin} {
					f.admitted(t, route, target, body, role)
				}
			}
		})
	}
}

func TestArtifactMutationTenantOwnershipIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	digest := f.own["sha"]
	mustExec(t, f.pool, `INSERT INTO artifacts (sha256, org_id, trail_id, name, type)
		VALUES ($1, $2, $3, 'registered fixture', 'docker')`, digest, f.own["org"], f.own["trail"])

	const route = "POST /api/v1/artifacts"
	body := fmt.Sprintf(`{"sha256":%q,"trail_id":%q,"name":"fixture","type":"docker"}`, digest, f.other["trail"])
	f.denied(t, route, body, routeSession(t, f.server, f.other["org"], auth.RoleWriter, time.Hour),
		http.StatusConflict, "artifact could not be registered")

	newTrail := uuid.NewString()
	mustExec(t, f.pool, `INSERT INTO trails (id, flow_id, name) VALUES ($1, $2, 'new fixture trail')`, newTrail, f.own["flow"])
	body = fmt.Sprintf(`{"sha256":%q,"trail_id":%q,"name":"fixture","type":"docker"}`, digest, newTrail)
	serveMutation(t, f.handler, route, body, f.sessions[auth.RoleWriter], http.StatusCreated, "")
	var recordedTrail string
	if err := f.pool.QueryRow(`SELECT trail_id FROM artifacts WHERE sha256 = $1`, digest).Scan(&recordedTrail); err != nil || recordedTrail != newTrail {
		t.Fatalf("artifact trail = %q, want %q, query error %v", recordedTrail, newTrail, err)
	}
}

func (f *routeAuthFixture) stubGitProvider(t *testing.T) {
	t.Helper()
	const listPath = "/repos/fixture/project/attestations/sha256:"
	statement := fmt.Sprintf(`{"predicateType":"https://slsa.dev/provenance/v1",
		"subject":[{"name":"fixture","digest":{"sha256":%q}}],
		"predicate":{"runDetails":{"builder":{"id":"https://builder.example.invalid/fixture"}}}}`, f.own["sha"])
	t.Setenv("AUTH_MATRIX_GIT_TOKEN", "fixture-git-token")
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer fixture-git-token" {
			t.Errorf("unexpected git fixture request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repos/fixture/project/branches/main/protection":
			fmt.Fprint(w, `{"required_pull_request_reviews":{"required_approving_review_count":1}}`)
		case listPath + f.own["sha"]:
			fmt.Fprintf(w, `{"attestations":[{"bundle_url":%q}]}`, "http://"+r.Host+"/bundle")
		case "/bundle":
			fmt.Fprintf(w, `{"dsseEnvelope":{"payload":%q}}`, base64.StdEncoding.EncodeToString([]byte(statement)))
		default:
			t.Errorf("unexpected git fixture endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(stub.Close)
	f.server.httpClient = stub.Client()
	mustExec(t, f.pool, `INSERT INTO tenant_git_providers (org_id,provider,host,api_base,token_path,enabled)
		VALUES ($1,'github','fixture-api.example.invalid',$2,'AUTH_MATRIX_GIT_TOKEN',true)`, f.own["org"], stub.URL)
}

func TestMutationCredentialsIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	const controlRoute = "POST /api/v1/controls"
	const flowRoute = "PUT /api/v1/flows"
	const control = `{"key":"credential-check","name":"Credential check","required_types":[]}`
	flow := fmt.Sprintf(`{"id":%q,"name":"credential-check"}`, f.own["flow"])
	admin := f.sessions[auth.RoleAdmin]

	t.Run("session", func(t *testing.T) {
		f.denied(t, controlRoute, control, routeSession(t, f.server, f.own["org"], auth.RoleAdmin, -time.Hour), 401, "authentication required")
		t.Setenv("FIDES_API_TOKEN", "")
		t.Setenv("FIDES_API_ORG_ID", "")
		serveMutation(t, f.handler, controlRoute, control, admin, 201, "")
	})

	t.Run("legacy bearer", func(t *testing.T) {
		f.denied(t, controlRoute, control, routeBearer("wrong-fixture-token"), 401, "invalid credentials")
		serveMutation(t, f.handler, controlRoute, control, routeBearer(fixtureBearer), 201, "")
		t.Setenv("FIDES_API_ORG_ID", f.other["org"])
		f.denied(t, flowRoute, flow, routeBearer(fixtureBearer), 404, "flow not found")
		t.Setenv("FIDES_API_ORG_ID", "")
		f.denied(t, controlRoute, control, routeBearer(fixtureBearer), 503, "service token tenant (FIDES_API_ORG_ID) is not configured")
	})

	t.Run("portal basic", func(t *testing.T) {
		t.Setenv("PORTAL_USERNAME", "portal@example.invalid")
		t.Setenv("PORTAL_PASSWORD", fixturePassword)
		t.Setenv("FIDES_API_TOKEN", "")
		basic := func(r *http.Request) { r.SetBasicAuth("portal@example.invalid", fixturePassword) }
		serveMutation(t, f.handler, controlRoute, control, basic, 201, "")
		mustExec(t, f.pool, `INSERT INTO users (org_id,name,email,role) VALUES ($1,'Portal','portal@example.invalid','Viewer')`, f.own["org"])
		f.denied(t, controlRoute, control, basic, 403, "")
		t.Setenv("FIDES_API_ORG_ID", "")
		f.denied(t, controlRoute, control, basic, 503, "portal tenant (FIDES_API_ORG_ID) is not configured")
	})

	t.Run("delegated approvals", func(t *testing.T) {
		target := "POST /api/v1/trails/" + f.own["trail"] + "/approvals"
		const body = `{"reason":"fixture review","on_behalf_of":"own@example.invalid"}`
		for _, test := range []struct {
			enabled, kind string
			delegated     bool
		}{
			{"false", "service", false},
			{"true", "session", true},
		} {
			t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", test.enabled)
			rec := serveMutation(t, f.handler, target, body, routeBearer(fixtureBearer), 201, "")
			var reply struct {
				Kind        string `json:"kind"`
				ApprovedBy  string `json:"approved_by"`
				DelegatedBy string `json:"delegated_by"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Kind != test.kind || (reply.ApprovedBy == "own@example.invalid") != test.delegated ||
				(reply.DelegatedBy != "") != test.delegated {
				t.Errorf("delegation=%s: unexpected attribution %s", test.enabled, rec.Body)
			}
		}
	})

	t.Run("service-account bearer", func(t *testing.T) {
		issue := "POST /api/v1/tenant/service-accounts/" + f.own["account"] + "/keys"
		rec := serveMutation(t, f.handler, issue, `{"label":"matrix key","expires_hours":1}`, admin, 201, "")
		var key struct {
			Token  string `json:"api_key"`
			Prefix string `json:"prefix"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &key); err != nil || key.Token == "" || key.Prefix == "" {
			t.Fatal("key issuance did not return a usable key")
		}
		writer := routeBearer(key.Token)
		t.Setenv("FIDES_API_ORG_ID", f.other["org"])
		const trailRoute = "POST /api/v1/trails"
		trailBody := fmt.Sprintf(`{"flow_id":%q,"name":"credential-writer"}`, f.own["flow"])
		serveMutation(t, f.handler, trailRoute, trailBody, writer, http.StatusCreated, "")
		var count int
		if err := f.pool.QueryRow(`SELECT count(*) FROM trails WHERE flow_id=$1 AND name='credential-writer'`, f.own["flow"]).Scan(&count); err != nil || count != 1 {
			t.Fatalf("writer key did not create one own-tenant trail: %d, %v", count, err)
		}

		// Auth stamps successful key verification even when the handler denies
		// authorization. Require that stamp and no other row changes.
		mustExec(t, f.pool, `UPDATE service_account_keys SET last_used_at=NULL WHERE prefix=$1`, key.Prefix)
		keyState := func() string {
			var state string
			if err := f.pool.QueryRow(`SELECT jsonb_agg(CASE WHEN k.prefix=$1 THEN to_jsonb(k)-'last_used_at'
				ELSE to_jsonb(k) || jsonb_build_object('xmin',k.xmin::text) END ORDER BY k.id)
				FROM service_account_keys k`, key.Prefix).Scan(&state); err != nil {
				t.Fatal(err)
			}
			return state
		}
		keysBefore := keyState()
		before := f.snapshot(t)
		serveMutation(t, f.handler, controlRoute, control, writer, 403, "")
		if changed := changedRouteTables(before, f.snapshot(t)); len(changed) != 1 || changed[0] != "service_account_keys" {
			t.Errorf("role denial should only record key usage, changed %v", changed)
		}
		if keyState() != keysBefore {
			t.Error("role denial changed key state beyond the authenticated key's usage timestamp")
		}
		var keyID string
		if err := f.pool.QueryRow(`SELECT id FROM service_account_keys WHERE prefix=$1 AND last_used_at IS NOT NULL`, key.Prefix).Scan(&keyID); err != nil {
			t.Fatal(err)
		}
		t.Setenv("FIDES_API_TOKEN", "")
		f.denied(t, trailRoute, trailBody, writer, 503, "API authentication is not configured on the server")
		t.Setenv("FIDES_API_TOKEN", fixtureBearer)
		t.Setenv("FIDES_API_ORG_ID", "")
		trailBody = fmt.Sprintf(`{"flow_id":%q,"name":"credential-no-legacy-tenant"}`, f.own["flow"])
		serveMutation(t, f.handler, trailRoute, trailBody, writer, http.StatusCreated, "")

		mustExec(t, f.pool, `UPDATE service_account_keys SET expires_at=now()-interval '1 minute' WHERE id=$1`, keyID)
		f.denied(t, trailRoute, trailBody, writer, 401, "invalid credentials")
		mustExec(t, f.pool, `UPDATE service_account_keys SET expires_at=NULL WHERE id=$1`, keyID)
		mustExec(t, f.pool, `UPDATE service_accounts SET enabled=false WHERE id=$1`, f.own["account"])
		f.denied(t, trailRoute, trailBody, writer, 401, "invalid credentials")
		mustExec(t, f.pool, `UPDATE service_accounts SET enabled=true WHERE id=$1`, f.own["account"])

		revoke := "DELETE /api/v1/tenant/service-accounts/" + f.own["account"] + "/keys/" + keyID
		serveMutation(t, f.handler, revoke, "", admin, 200, "")
		f.denied(t, trailRoute, trailBody, writer, 401, "invalid credentials")
	})
}

func TestExplicitApprovalDelegationIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	mustExec(t, f.pool, `UPDATE service_accounts SET role = $1, may_delegate_approvals = true WHERE id = $2`,
		auth.RoleViewer, f.own["account"])
	issue := "POST /api/v1/tenant/service-accounts/" + f.own["account"] + "/keys"
	rec := serveMutation(t, f.handler, issue, `{"label":"approval-capability","expires_hours":1}`,
		f.sessions[auth.RoleAdmin], http.StatusCreated, "")
	var key struct {
		Token string `json:"api_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &key); err != nil || key.Token == "" {
		t.Fatalf("key issuance did not return an API key: %v", err)
	}
	target := "POST /api/v1/trails/" + f.own["trail"] + "/approvals"
	const body = `{"reason":"fixture review","on_behalf_of":"own@example.invalid"}`
	credential := routeBearer(key.Token)
	before := f.snapshot(t)["trail_approvals"]
	f.denied(t, target, "{", f.sessions[auth.RoleWriter], http.StatusBadRequest, "invalid request")
	serveMutation(t, f.handler, target, body, credential, http.StatusForbidden, "")
	if f.snapshot(t)["trail_approvals"] != before {
		t.Fatal("disabled delegation wrote an approval")
	}

	t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
	serveMutation(t, f.handler, target, `{"reason":"fixture review"}`, credential, http.StatusForbidden, "")
	if f.snapshot(t)["trail_approvals"] != before {
		t.Fatal("nondelegated request wrote an approval")
	}
	rec = serveMutation(t, f.handler, target, body, credential, http.StatusCreated, "")
	var approval struct {
		ApprovedBy  string `json:"approved_by"`
		Kind        string `json:"kind"`
		DelegatedBy string `json:"delegated_by"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &approval); err != nil || approval.ApprovedBy != "own@example.invalid" ||
		approval.Kind != "session" || approval.DelegatedBy == "" {
		t.Fatalf("explicit delegation was not preserved: %s (%v)", rec.Body, err)
	}
}

func TestPublicMutationAuthorizationIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	t.Setenv("FIDES_API_TOKEN", "")
	for _, route := range mutationRoutes {
		switch route.auth {
		case signedCallback:
			t.Run(route.pattern, func(t *testing.T) { f.checkSignedCallback(t, route.pattern) })
		case localLogin:
			t.Run(route.pattern, func(t *testing.T) { f.checkLocalLogin(t, route.pattern) })
		case admissionTLS:
			t.Run(route.pattern, func(t *testing.T) { f.checkAdmission(t, route.pattern) })
		case ssoState:
			// The login and callback are a single state exchange.
			switch route.pattern {
			case "GET /api/v1/auth/login":
				t.Run("SSO state exchange", func(t *testing.T) { f.checkSSO(t, route.pattern, "GET /api/v1/auth/callback") })
			case "GET /api/v1/auth/callback":
			default:
				t.Errorf("add a public SSO assertion for %s", route.pattern)
			}
		}
	}
}

func (f *routeAuthFixture) checkSignedCallback(t *testing.T, pattern string) {
	const secret = "fixture-inbound-secret"
	t.Setenv("AUTH_MATRIX_SIGNING_SECRET", secret)
	for _, provider := range []struct{ name, header, body string }{
		{"github", "X-Hub-Signature-256", `{"ref":"refs/heads/main","after":"0123456789abcdef","repository":{"full_name":"fixture/github","clone_url":"https://git.example.invalid/fixture/github"}}`},
		{"gitlab", "X-Gitlab-Token", `{"object_kind":"push","ref":"refs/heads/main","checkout_sha":"0123456789abcdef","project":{"path_with_namespace":"fixture/gitlab","git_http_url":"https://git.example.invalid/fixture/gitlab"}}`},
	} {
		t.Run(provider.name, func(t *testing.T) {
			host := provider.name + ".example.invalid"
			mustExec(t, f.pool, `INSERT INTO tenant_git_providers (org_id,provider,host,api_base,token_path,inbound_secret_path,enabled)
				VALUES ($1,$2,$3,$4,'UNUSED_FETCH_TOKEN','AUTH_MATRIX_SIGNING_SECRET',true)`,
				f.own["org"], provider.name, host, "https://"+host)
			target := strings.ReplaceAll(pattern, "{provider}", provider.name) + "?org=" + f.own["org"]
			f.denied(t, target, provider.body, nil, 401, "invalid webhook signature")
			f.denied(t, target, provider.body, func(r *http.Request) {
				r.Header.Set(provider.header, "fixture-invalid-signature")
			}, http.StatusUnauthorized, "invalid webhook signature")
			value := secret
			if provider.name == "github" {
				mac := hmac.New(sha256.New, []byte(secret))
				mac.Write([]byte(provider.body))
				value = fmt.Sprintf("sha256=%x", mac.Sum(nil))
			}
			credential := func(r *http.Request) { r.Header.Set(provider.header, value) }
			serveMutation(t, f.handler, target, provider.body, credential, 201, "")
			var count int
			if err := f.pool.QueryRow(`SELECT count(*) FROM trails t JOIN flows f ON f.id=t.flow_id
				WHERE f.org_id=$1 AND f.name=$2 AND t.git_commit='0123456789abcdef'`,
				f.own["org"], "fixture/"+provider.name).Scan(&count); err != nil || count != 1 {
				t.Fatalf("signed fixture push: want one tenant trail, got %d (%v)", count, err)
			}
		})
	}
}

func (f *routeAuthFixture) checkLocalLogin(t *testing.T, pattern string) {
	t.Setenv("FIDES_API_ORG_ID", "")
	const login = `{"username":"own@example.invalid","password":"auth-fixture-local-password"}`
	f.denied(t, pattern, login, nil, 403, "local authentication is not configured")
	t.Setenv("PORTAL_USERNAME", "portal@example.invalid")
	t.Setenv("PORTAL_PASSWORD", fixturePassword)
	const portal = `{"username":"portal@example.invalid","password":"auth-fixture-local-password"}`
	f.denied(t, pattern, portal, nil, 503, "portal tenant (FIDES_API_ORG_ID) is not configured")

	t.Setenv("FIDES_API_ORG_ID", f.own["org"])
	serveMutation(t, f.handler, "POST /api/v1/tenant/users/"+f.own["user"]+"/password",
		`{"password":"auth-fixture-local-password"}`, f.sessions[auth.RoleAdmin], 200, "")
	f.denied(t, pattern, `{"username":"own@example.invalid","password":"wrong-fixture-password"}`, nil, 401, "invalid username or password")

	const control = `{"key":"local-login","name":"Local login","required_types":[]}`
	writer := serveMutation(t, f.handler, pattern, login, nil, 200, "")
	f.denied(t, "POST /api/v1/controls", control, routeCookie(loginCookie(t, writer)), 403, "")
	admin := serveMutation(t, f.handler, pattern, portal, nil, 200, "")
	serveMutation(t, f.handler, "POST /api/v1/controls", control, routeCookie(loginCookie(t, admin)), 201, "")
}

func loginCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" && c.HttpOnly && c.Secure {
			return c
		}
	}
	t.Fatal("expected a secure session cookie")
	return nil
}

func (f *routeAuthFixture) checkAdmission(t *testing.T, pattern string) {
	body := fmt.Sprintf(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",
		"request":{"uid":"fixture-pod","object":{"spec":{"containers":[{"name":"fixture","image":"images.example.invalid/fixture@sha256:%s"}]}}}}`, f.own["sha"])
	for _, test := range []struct {
		name, org, mode string
		allowed         bool
	}{
		{"unconfigured", "", "enforce", true},
		{"audit", f.own["org"], "audit", true},
		{"enforce", f.own["org"], "enforce", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("FIDES_ADMISSION_ORG_ID", test.org)
			t.Setenv("FIDES_ADMISSION_MODE", test.mode)
			before := f.snapshot(t)
			rec := serveMutation(t, f.handler, pattern, body, nil, 200, "")
			var review admission.AdmissionReview
			if err := json.Unmarshal(rec.Body.Bytes(), &review); err != nil || review.Response == nil {
				t.Fatalf("invalid admission response: %s", rec.Body)
			}
			resp := review.Response
			warned := len(resp.Warnings) > 0
			if resp.UID != "fixture-pod" || resp.Allowed != test.allowed || (test.allowed && !warned) ||
				(!test.allowed && (resp.Status == nil || !strings.Contains(resp.Status.Message, "is not registered in Fides"))) {
				t.Errorf("unexpected admission verdict: %s", rec.Body)
			}
			if changed := changedRouteTables(before, f.snapshot(t)); len(changed) > 0 {
				t.Errorf("admission review wrote to %v", changed)
			}
		})
	}
}

func (f *routeAuthFixture) checkSSO(t *testing.T, login, callback string) {
	t.Setenv("AUTH_MATRIX_OAUTH_SECRET", "fixture-oauth-secret")
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/token" && r.FormValue("code") == "fixture-code":
			fmt.Fprint(w, `{"access_token":"fixture-oauth-token"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/userinfo" && r.Header.Get("Authorization") == "Bearer fixture-oauth-token":
			fmt.Fprint(w, `{"email":"own@example.invalid"}`)
		default:
			t.Errorf("unexpected OAuth request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	f.server.httpClient = provider.Client()
	mustExec(t, f.pool, `INSERT INTO tenant_auth_configs
		(org_id,provider_name,client_id,client_secret_path,auth_url,token_url,userinfo_url,redirect_uri)
		VALUES ($1,'github','fixture-client','AUTH_MATRIX_OAUTH_SECRET',$2,$3,$4,'https://fides.example.invalid/api/v1/auth/callback')`,
		f.own["org"], provider.URL+"/authorize", provider.URL+"/token", provider.URL+"/userinfo")

	f.denied(t, callback+"?code=fixture-code&state=unknown", "", nil, 400, "invalid or expired login state")
	rec := serveMutation(t, f.handler, login+"?provider=github&org_id="+f.own["org"], "", nil, 307, "")
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := location.Query().Get("state")
	if location.Path != "/authorize" || state == "" {
		t.Fatal("SSO login did not redirect to the fixture provider with a state")
	}
	target := callback + "?code=fixture-code&state=" + url.QueryEscape(state)
	rec = serveMutation(t, f.handler, target, "", nil, 307, "")
	f.denied(t, target, "", nil, 400, "invalid or expired login state")
	credential := routeCookie(loginCookie(t, rec))
	f.denied(t, "POST /api/v1/controls", `{"key":"sso","name":"SSO","required_types":[]}`, credential, 403, "")
	serveMutation(t, f.handler, "POST /api/v1/trails",
		fmt.Sprintf(`{"flow_id":%q,"name":"sso-fixture"}`, f.own["flow"]), credential, 201, "")
}
