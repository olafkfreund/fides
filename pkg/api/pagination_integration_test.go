package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"fides/pkg/auth"
	"fides/pkg/db"
)

type countingListQueries struct {
	db.Querier
	count int
	fail  int
}

func (q *countingListQueries) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	q.count++
	if q.count == q.fail {
		return nil, errors.New("fixture enrichment query failure")
	}
	return q.Querier.QueryContext(ctx, query, args...)
}

func (q *countingListQueries) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	q.count++
	return q.Querier.QueryRowContext(ctx, query, args...)
}

func TestIntegrationListPagination(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run pagination against PostgreSQL")
	}
	t.Setenv("FIDES_RLS_ENABLED", "false")
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx := context.Background()
	if err := db.WithSchemaLock(ctx, pool, func(ctx context.Context) error { return db.Migrate(ctx, pool) }); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	org, otherOrg, flow, trail, env, emptyEnv, account := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest, secondDigest, foreignDigest := uuid.NewString(), uuid.NewString(), uuid.NewString()
	// Defaults in one transaction give every created_at tie the same time.
	insert := func(query string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("fixture %s: %v", query, err)
		}
	}
	insert(`INSERT INTO organizations (id,name) VALUES ($1,$2), ($3,$4)`, org, org.String(), otherOrg, otherOrg.String())
	insert(`INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'one'), (gen_random_uuid(),$2,'two'), (gen_random_uuid(),$3,'other')`, flow, org, otherOrg)
	insert(`INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'one'), (gen_random_uuid(),$2,'two')`, trail, flow)
	insert(`INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'one','k8s'), ($3,$2,'two','k8s')`, env, org, emptyEnv)
	insert(`INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'one','binary'), ($4,$2,$3,'two','binary'), ($5,$6,$3,'other','binary')`,
		digest, org, trail, secondDigest, foreignDigest, otherOrg)
	insert(`INSERT INTO attestations (trail_id, artifact_sha256, name, type_name, payload, is_compliant)
		VALUES ($1,$2,'older','sbom','["older"]',true), ($1,$2,'newer','sbom-scan','{"components":["new"]}',false)`, trail, digest)
	insert(`UPDATE attestations SET created_at = created_at - interval '1 second' WHERE trail_id = $1 AND name = 'older'`, trail)
	insert(`INSERT INTO attestations (trail_id,name,type_name,payload)
		SELECT $1, 'flag', $2, jsonb_build_object('flag_key', n::text, 'environment', 'test',
			'old_state', 'off', 'new_state', 'on', 'actor', 'tester', 'source', 'fixture')
		FROM generate_series(1,2) n`, trail, FlagChangedAttestationType)
	insert(`INSERT INTO sbom_components (org_id,artifact_sha256,name) VALUES ($1,$2,'one'), ($1,$2,'two')`, org, digest)
	insert(`INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind) VALUES ($1,$2,'one','session'), ($1,$2,'two','session')`, org, trail)
	insert(`INSERT INTO deployment_anchors (org_id,trail_id,ci_sys_id) VALUES ($1,$2,'one'), ($1,$2,'two')`, org, trail)
	insert(`INSERT INTO controls (org_id,key,name) VALUES ($1,'one','one'), ($1,'two','two')`, org)
	insert(`INSERT INTO control_exceptions (org_id,control_key,reason,expires_at) VALUES ($1,'one','fixture',now()), ($1,'two','fixture',now())`, org)
	insert(`INSERT INTO service_owners (org_id,service) VALUES ($1,'one'), ($1,'two')`, org)
	insert(`INSERT INTO training_records (org_id,person,course) VALUES ($1,'one','test'), ($1,'two','test')`, org)
	insert(`INSERT INTO logical_environments (org_id,name) VALUES ($1,'one'), ($1,'two')`, org)
	insert(`INSERT INTO environment_policies (environment_id,name) VALUES ($1,'one'), ($1,'two')`, env)
	insert(`INSERT INTO environment_allowlist (environment_id,artifact_sha256) VALUES ($1,$2), ($1,'previous')`, env, foreignDigest)
	insert(`INSERT INTO remediation_actions (org_id, domain, environment_id, proposed_by) VALUES ($1,'drift',$2,'one'), ($1,'drift',$2,'two')`, org, env)
	insert(`INSERT INTO policies (org_id,name,rules) VALUES ($1,'one','{}'), ($1,'two','{}')`, org)
	insert(`INSERT INTO llm_assessments (attestation_id,model_provider,model_name,prompt_template_version,assessment_raw,compliance_score)
		SELECT id,'fixture','fixture','1','assessment',100 FROM attestations WHERE trail_id = $1 AND type_name IN ('sbom','sbom-scan')`, trail)
	insert(`INSERT INTO tenant_webhooks (org_id,name,url,secret_path) VALUES ($1,'one','https://example.test','fixture'), ($1,'two','https://example.test','fixture')`, org)
	insert(`INSERT INTO tenant_git_providers (org_id,provider,host,api_base,token_path)
		VALUES ($1,'github','one.test','https://example.test','fixture'), ($1,'github','two.test','https://example.test','fixture')`, org)
	insert(`INSERT INTO integration_events (org_id,event_type,payload) VALUES ($1,'one','{}'), ($1,'two','{}')`, org)
	insert(`INSERT INTO environment_mcp_servers (environment_id,name) VALUES ($1,'one'), ($1,'two')`, env)
	insert(`INSERT INTO users (org_id,name,email,groups) VALUES ($1,'same',$2,'{}'), ($1,'same',$3,'{}')`, org, org.String()+"a@example.test", org.String()+"b@example.test")
	insert(`INSERT INTO service_accounts (id,org_id,name) VALUES ($1,$2,'one'), (gen_random_uuid(),$2,'two')`, account, org)
	insert(`INSERT INTO service_account_keys (service_account_id,prefix,key_hash) VALUES ($1,$2,'fixture'), ($1,$3,'fixture')`, account, org.String()[:12]+"a", org.String()[:12]+"b")
	insert(`INSERT INTO sso_group_mappings (org_id,external_group,role) VALUES ($1,'one','Viewer'), ($1,'two','Viewer')`, org)

	newest, historical := uuid.New(), uuid.New()
	insert(`INSERT INTO environment_snapshots (id,environment_id,created_at)
		VALUES ($1,$2,now()), ($3,$2,now()-interval '1 second'), (gen_random_uuid(),$4,now())`, newest, env, historical, emptyEnv)
	insert(`INSERT INTO snapshot_artifacts (snapshot_id,service_name,runtime_digest,artifact_sha256)
		VALUES ($1,'registered',$3,$3), ($1,'approved',$4,NULL), ($1,'upgrade','current',NULL), ($2,'upgrade','previous',NULL)`,
		newest, historical, digest, foreignDigest)

	srv := &Server{DB: pool, Sessions: auth.NewSessionStore()}
	routes := srv.Routes()
	queries := &countingListQueries{Querier: tx}
	ctx = db.WithQuerier(ctx, queries)
	makeSession := func(orgID uuid.UUID) string {
		token, err := srv.Sessions.Create(auth.Principal{OrgID: orgID, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	token, otherToken := makeSession(org), makeSession(otherOrg)
	get := func(path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		queries.count = 0
		routes.ServeHTTP(rec, req)
		return rec
	}
	array := func(t *testing.T, rec *httptest.ResponseRecorder, size int) []map[string]any {
		t.Helper()
		var items []map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &items) != nil || items == nil || len(items) != size {
			t.Fatalf("want array of %d items, got HTTP %d %s", size, rec.Code, rec.Body.String())
		}
		return items
	}
	next := func(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
		t.Helper()
		header := rec.Header().Get("Link")
		ref, ok := strings.CutSuffix(strings.TrimPrefix(header, "<"), `>; rel="next"`)
		link, err := url.Parse(ref)
		if !strings.HasPrefix(header, "<") || !ok || err != nil || link.Host != "" || link.IsAbs() || !strings.HasPrefix(link.Path, "/api/v1/") || !link.Query().Has("cursor") {
			t.Fatalf("invalid relative next link %q", header)
		}
		return link
	}

	orgPage := get("/api/v1/orgs?limit=1", token)
	if items := array(t, orgPage, 1); items[0]["id"] != org.String() || orgPage.Header().Get("Link") != "" {
		t.Fatalf("single tenant organization page: %s, Link %q", orgPage.Body.String(), orgPage.Header().Get("Link"))
	}
	for _, path := range []string{
		"/flows", "/flows/" + flow.String() + "/trails", "/flows/" + flow.String() + "/artifacts",
		"/trails/" + trail.String() + "/approvals", "/trails/" + trail.String() + "/deployment-anchors",
		"/search/artifacts", "/search/attestations?type=" + FlagChangedAttestationType, "/search/components",
		"/controls", "/exceptions", "/services", "/training", "/logical-environments",
		"/environments/" + env.String() + "/policies", "/environments/" + env.String() + "/allowlist",
		"/remediation?status=proposed&environment_id=" + env.String(), "/artifacts", "/environments", "/policies",
		"/ai-assessments", "/tenant/webhooks", "/tenant/git-providers", "/tenant/servicenow/events",
		"/flags/history", "/environments/mcp?environment_id=" + env.String(), "/tenant/users",
		"/tenant/service-accounts", "/tenant/service-accounts/" + account.String() + "/keys", "/tenant/group-mappings",
	} {
		t.Run(path, func(t *testing.T) {
			start, err := url.Parse("/api/v1" + path)
			if err != nil {
				t.Fatal(err)
			}
			q := start.Query()
			q.Set("limit", "1")
			start.RawQuery = q.Encode()
			first := get(start.RequestURI(), token)
			one := array(t, first, 1)
			link := next(t, first)
			if link.Path != start.Path || link.Query().Get("limit") != "1" {
				t.Fatalf("next link changed path or limit: %s", link)
			}
			second := get(link.RequestURI(), token)
			two := array(t, second, 1)
			if reflect.DeepEqual(one, two) || second.Header().Get("Link") != "" {
				t.Fatalf("duplicate row or extra link: first=%v second=%v link=%q", one, two, second.Header().Get("Link"))
			}
		})
	}

	t.Run("scope and validation", func(t *testing.T) {
		link := next(t, get("/api/v1/search/artifacts?limit=1&name=o", token))
		if link.Query().Get("name") != "o" {
			t.Fatal("filter lost from next link")
		}
		for _, tc := range []struct{ path, token string }{
			{link.RequestURI(), otherToken},
			{strings.Replace(link.RequestURI(), "/search/artifacts", "/artifacts", 1), token},
			{strings.Replace(link.RequestURI(), "name=o", "name=one", 1), token},
			{"/api/v1/flows?limit=0", token}, {"/api/v1/flows?limit=501", token},
			{"/api/v1/flows?limit=x", token}, {"/api/v1/flows?limit=", token},
			{"/api/v1/flows?limit=1&limit=2", token}, {"/api/v1/flows?cursor=!", token},
			{"/api/v1/flows?cursor=", token}, {"/api/v1/flows?cursor=x&cursor=x", token},
			{"/api/v1/flows?cursor=%ZZ", token},
		} {
			if rec := get(tc.path, tc.token); rec.Code != http.StatusBadRequest || rec.Header().Get("Link") != "" || queries.count != 0 {
				t.Errorf("%s: HTTP %d, %d queries", tc.path, rec.Code, queries.count)
			}
		}
		link = next(t, get("/api/v1/environments/"+env.String()+"/allowlist?limit=1", token))
		if rec := get(strings.Replace(link.RequestURI(), env.String(), emptyEnv.String(), 1), token); rec.Code != http.StatusBadRequest {
			t.Fatalf("parent mismatch: HTTP %d", rec.Code)
		}
		if rec := get(link.RequestURI()+"&sha="+foreignDigest, token); rec.Code != http.StatusBadRequest {
			t.Fatalf("list cursor used for digest lookup: HTTP %d", rec.Code)
		}
		if rec := get("/api/v1/environments/"+env.String()+"/allowlist?sha="+foreignDigest, token); rec.Code != http.StatusOK ||
			rec.Header().Get("Link") != "" || !strings.Contains(rec.Body.String(), `"approved":true`) {
			t.Fatalf("single digest lookup: HTTP %d %s", rec.Code, rec.Body.String())
		}
		rec := get("/api/v1/controls", otherToken)
		array(t, rec, 0)
		if rec.Header().Get("Link") != "" {
			t.Fatal("empty tenant page emitted a next link")
		}
		link = next(t, get("/api/v1/flows?limit=1", token))
		q := link.Query()
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		if err != nil {
			t.Fatal(err)
		}
		var cursor listCursor
		if err := json.Unmarshal(raw, &cursor); err != nil {
			t.Fatal(err)
		}
		badUUID := "invalid"
		for _, invalid := range []listCursor{
			{Version: 2, Scope: cursor.Scope, Keys: cursor.Keys},
			{Version: cursor.Version, Scope: cursor.Scope, Keys: []*string{cursor.Keys[0], &badUUID}},
		} {
			raw, _ := json.Marshal(invalid)
			q.Set("cursor", base64.RawURLEncoding.EncodeToString(raw))
			link.RawQuery = q.Encode()
			if rec := get(link.RequestURI(), token); rec.Code != http.StatusBadRequest || queries.count != 0 {
				t.Errorf("invalid version or key: HTTP %d, %d queries", rec.Code, queries.count)
			}
		}
	})

	t.Run("name filters", func(t *testing.T) {
		for _, path := range []string{"/api/v1/flows", "/api/v1/environments"} {
			items := array(t, get(path+"?limit=1&name=TW", token), 1)
			if items[0]["name"] != "two" {
				t.Fatalf("filter on %s returned %v", path, items)
			}
		}
		items := array(t, get("/api/v1/search/attestations?limit=1&name=NEW", token), 1)
		if items[0]["name"] != "newer" {
			t.Fatalf("attestation name filter returned %v", items)
		}
	})

	t.Run("batched enrichment", func(t *testing.T) {
		for _, path := range []string{"/api/v1/environments", "/api/v1/artifacts"} {
			for _, page := range []struct {
				query string
				size  int
			}{{"?limit=1", 1}, {"?limit=500", 2}} {
				items := array(t, get(path+page.query, token), page.size)
				if queries.count != 2 {
					t.Fatalf("%s%s used %d queries, want 2", path, page.query, queries.count)
				}
				if path == "/api/v1/environments" {
					first := items[0]
					if len(first["running"].([]any)) != 3 || len(first["drifts"].([]any)) != 1 ||
						!reflect.DeepEqual(first["shadowChanges"], []any{shadowMessage("upgrade", "current", true)}) {
						t.Fatalf("runtime verdict: %v", first)
					}
				} else if page.size == 2 {
					for _, item := range items {
						if item["sha256"] == digest && (item["sbom_status"] != "Non-Compliant" || !reflect.DeepEqual(item["sbom"], []any{"new"})) ||
							item["sha256"] == secondDigest && (item["sbom_status"] != "Pending" || !reflect.DeepEqual(item["sbom"], []any{})) {
							t.Fatalf("unexpected SBOM summary: %v", item)
						}
					}
				}
			}
			queries.fail = 2
			rec := get(path+"?limit=1", token)
			queries.fail = 0
			if rec.Code != http.StatusInternalServerError || rec.Header().Get("Link") != "" {
				t.Fatalf("%s error response: HTTP %d, Link %q", path, rec.Code, rec.Header().Get("Link"))
			}
		}
	})

	t.Run("environment audit enrichment failure", func(t *testing.T) {
		queries.fail = 2
		defer func() { queries.fail = 0 }()
		rec := get("/api/v1/environments/export?environment_id="+env.String(), token)
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Content-Disposition") != "" {
			t.Fatalf("audit export returned a downloadable report on query failure: HTTP %d, headers %v", rec.Code, rec.Header())
		}
	})

	t.Run("report retains full training evidence", func(t *testing.T) {
		rec := get("/api/v1/audit-pack?limit=1", token)
		var report struct {
			Training []json.RawMessage `json:"training"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &report) != nil ||
			len(report.Training) != 2 || rec.Header().Get("Link") != "" {
			t.Fatalf("audit pack HTTP %d, training records=%d, Link=%q", rec.Code, len(report.Training), rec.Header().Get("Link"))
		}
	})

	t.Run("default and maximum", func(t *testing.T) {
		insert(`INSERT INTO flows (org_id,name) SELECT $1,'fixture-' || n FROM generate_series(1,499) n`, org)
		rec := get("/api/v1/flows", token)
		array(t, rec, 100)
		link := next(t, rec)
		q := link.Query()
		q.Set("limit", "500")
		link.RawQuery = q.Encode()
		rec = get(link.RequestURI(), token)
		array(t, rec, 401)
		if rec.Header().Get("Link") != "" {
			t.Fatal("terminal page emitted a next link")
		}
		rec = get("/api/v1/flows?limit=500", token)
		array(t, rec, 500)
		array(t, get(next(t, rec).RequestURI(), token), 1)
	})
}
