package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"fides/pkg/auth"
	"fides/pkg/crypto"
	"fides/pkg/db"
	"fides/pkg/ledger"
	"fides/pkg/models"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// E2E proof that with FIDES_RLS_ENABLED the full HTTP -> middleware ->
// scoped-conn -> handler chain isolates tenants via Postgres RLS while the
// server connects as a non-superuser role. Skipped unless FIDES_TEST_DB_DSN is
// set (a superuser DSN used for setup).
func TestRLSEndToEndTenantIsolation(t *testing.T) {
	superDSN := os.Getenv("FIDES_TEST_DB_DSN")
	if superDSN == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the RLS E2E test")
	}

	// --- Setup as superuser: schema, RLS, least-privilege app role, seed.
	super, err := sql.Open("postgres", superDSN)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so this closed the pool before the row cleanup below could use it.
	t.Cleanup(func() { super.Close() })
	if err := super.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	mustExec := func(q string, args ...any) {
		if _, err := super.Exec(q, args...); err != nil {
			t.Fatalf("exec failed: %v\nSQL: %.100s", err, q)
		}
	}
	if err := db.Migrate(context.Background(), super); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.ApplyRLS(context.Background(), super); err != nil {
		t.Fatalf("apply RLS: %v", err)
	}
	mustExec(`DO $$ BEGIN
	            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_e2e_app') THEN
	              CREATE ROLE fides_e2e_app LOGIN PASSWORD 'app';
	            END IF;
	          END $$;
	          GRANT USAGE ON SCHEMA public TO fides_e2e_app;
	          GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_e2e_app;
	          GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_e2e_app;`)

	orgA, orgB := uuid.New(), uuid.New()
	mustExec(`INSERT INTO organizations (id, name) VALUES ($1,$2),($3,$4)`,
		orgA, "A-"+orgA.String()[:8], orgB, "B-"+orgB.String()[:8])
	mustExec(`INSERT INTO flows (org_id, name, description) VALUES ($1,'flow-a','a'),($2,'flow-b','b')`, orgA, orgB)
	t.Cleanup(func() { _, _ = super.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB) })

	// --- The server's pool connects as the non-superuser app role so RLS applies.
	appDSN := withUserPassword(superDSN, "fides_e2e_app", "app")
	appPool, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()
	appPool.SetMaxOpenConns(2)
	if err := appPool.Ping(); err != nil {
		t.Fatalf("app ping: %v", err)
	}

	t.Setenv("FIDES_RLS_ENABLED", "true")
	t.Setenv("FIDES_API_TOKEN", "unused-but-required")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	srv := NewServer(appPool, nil, nil)
	tokenA, _ := srv.Sessions.Create(auth.Principal{OrgID: orgA, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
	tokenB, _ := srv.Sessions.Create(auth.Principal{OrgID: orgB, Role: auth.RoleViewer, Kind: "session"}, time.Hour, time.Now())

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	listFlowNames := func(sessionToken string) []string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/flows", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var flows []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&flows); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var names []string
		for _, f := range flows {
			names = append(names, f.Name)
		}
		return names
	}

	if got := listFlowNames(tokenA); len(got) != 1 || got[0] != "flow-a" {
		t.Fatalf("OrgA should see only flow-a via RLS, got %v", got)
	}
	if got := listFlowNames(tokenB); len(got) != 1 || got[0] != "flow-b" {
		t.Fatalf("OrgB should see only flow-b via RLS, got %v", got)
	}

	t.Run("keyed recording under RLS", func(t *testing.T) {
		var active bool
		if err := appPool.QueryRow(`SELECT row_security_active('recording_operations')`).Scan(&active); err != nil || !active {
			t.Fatalf("recording RLS active = %v, error = %v", active, err)
		}
		var flowID uuid.UUID
		if err := super.QueryRow(`SELECT id FROM flows WHERE org_id = $1 AND name = 'flow-a'`, orgA).Scan(&flowID); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := super.Exec(`DELETE FROM trails WHERE flow_id = $1 AND name = 'rls-keyed-recording'`, flowID); err != nil {
				t.Error(err)
			}
		})
		body := fmt.Sprintf(`{"flow_id":%q,"name":"rls-keyed-recording"}`, flowID)
		key := uuid.NewString()
		var first string
		for range 2 {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/trails", strings.NewReader(body))
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tokenA})
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)
			current := expectRecording(t, rec, http.StatusCreated)
			if first != "" && current != first {
				t.Fatal("keyed recording changed its committed response")
			}
			first = current
		}
		var visible int
		if err := appPool.QueryRow(`SELECT count(*) FROM recording_operations`).Scan(&visible); err != nil || visible != 0 {
			t.Fatalf("unscoped connection sees %d recordings, error = %v", visible, err)
		}
	})

	t.Run("concurrent scoped snapshots", func(t *testing.T) {
		var rlsActive bool
		if err := appPool.QueryRow(`SELECT row_security_active('environment_snapshots')`).Scan(&rlsActive); err != nil || !rlsActive {
			t.Fatalf("snapshot RLS active = %v, error = %v", rlsActive, err)
		}
		envs := [2]uuid.UUID{uuid.New(), uuid.New()}
		var tokens [2]string
		for i, org := range [2]uuid.UUID{orgA, orgB} {
			mustExec(`INSERT INTO environments (id, org_id, name, type) VALUES ($1,$2,'prod-k8s','k8s')`, envs[i], org)
			var err error
			tokens[i], err = srv.Sessions.Create(auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
			if err != nil {
				t.Fatalf("create session: %v", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		postSnapshot := func(token string, envID uuid.UUID, services ...string) (uuid.UUID, int, error) {
			var body reportSnapshotReq
			body.EnvironmentID = envID.String()
			for _, service := range services {
				body.Artifacts = append(body.Artifacts, struct {
					SHA256      string `json:"sha256"`
					ServiceName string `json:"service_name"`
				}{SHA256: uuid.NewString(), ServiceName: service})
			}
			raw, err := json.Marshal(body)
			if err != nil {
				return uuid.Nil, 0, err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/snapshots", strings.NewReader(string(raw)))
			if err != nil {
				return uuid.Nil, 0, err
			}
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
			req.Header.Set("Content-Type", "application/json")
			resp, err := ts.Client().Do(req)
			if err != nil {
				return uuid.Nil, 0, err
			}
			defer resp.Body.Close()
			var reported snapshotReportResponse
			if resp.StatusCode == http.StatusCreated {
				err = json.NewDecoder(resp.Body).Decode(&reported)
			}
			return reported.SnapshotID, resp.StatusCode, err
		}

		var writes sync.WaitGroup
		start := make(chan struct{})
		for i := range 8 {
			writes.Go(func() {
				<-start
				tenant := i % len(envs)
				id, status, err := postSnapshot(tokens[tenant], envs[tenant], "test-service")
				if err != nil || status != http.StatusCreated || id == uuid.Nil {
					t.Errorf("snapshot %d: id = %s, status = %d, error = %v", i, id, status, err)
					return
				}
				var env uuid.UUID
				if err := super.QueryRowContext(ctx, `SELECT environment_id FROM environment_snapshots WHERE id = $1`, id).Scan(&env); err != nil || env != envs[tenant] {
					t.Errorf("snapshot %s: stored environment = %s, want %s, error = %v", id, env, envs[tenant], err)
				}
			})
		}
		close(start)
		writes.Wait()
		if t.Failed() {
			t.FailNow()
		}

		for _, tc := range []struct {
			env      uuid.UUID
			status   int
			services []string
		}{
			{env: envs[1], status: http.StatusNotFound},
			{env: envs[0], status: http.StatusInternalServerError, services: []string{"valid-service", strings.Repeat("x", 256)}},
		} {
			if _, status, err := postSnapshot(tokens[0], tc.env, tc.services...); err != nil || status != tc.status {
				t.Fatalf("snapshot for %s: status = %d, want %d, error = %v", tc.env, status, tc.status, err)
			}
		}
		for _, env := range envs {
			var snapshots, artifacts int
			err := super.QueryRowContext(ctx, `SELECT COUNT(DISTINCT s.id), COUNT(a.id)
			FROM environment_snapshots s LEFT JOIN snapshot_artifacts a ON a.snapshot_id = s.id
			WHERE s.environment_id = $1`, env).Scan(&snapshots, &artifacts)
			if err != nil || snapshots != 4 || artifacts != 4 {
				t.Fatalf("environment %s: snapshots = %d, artifacts = %d, want 4 each, error = %v", env, snapshots, artifacts, err)
			}
		}

	})

	shaA, shaB := uuid.NewString(), uuid.NewString()
	mustExec(`INSERT INTO trails (flow_id, name)
		SELECT id, 'test-build' FROM flows WHERE org_id IN ($1,$2)`, orgA, orgB)
	mustExec(`INSERT INTO artifacts (sha256, org_id, trail_id, name, type)
		SELECT CASE WHEN f.org_id = $1 THEN $3::text ELSE $4::text END, f.org_id, t.id, f.name, 'binary'
		FROM trails t JOIN flows f ON f.id = t.flow_id WHERE f.org_id IN ($1,$2)`, orgA, orgB, shaA, shaB)
	mustExec(`INSERT INTO attestations (trail_id, artifact_sha256, name, type_name, payload)
		SELECT trail_id, sha256, 'sbom', 'sbom', jsonb_build_array(name) FROM artifacts WHERE sha256 IN ($1,$2)`, shaA, shaB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := func(method, path, token, body string, want int, dst any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: status = %d, want %d", method, path, resp.StatusCode, want)
		}
		if dst != nil {
			if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
				t.Fatal(err)
			}
		}
	}

	var flag struct {
		TrailID uuid.UUID `json:"trail_id"`
	}
	request(http.MethodPost, "/api/v1/flags/changed", tokenA,
		`{"flag_key":"checkout","environment":"prod","old_state":"off","new_state":"on","actor":"olaf","source":"unleash"}`,
		http.StatusCreated, &flag)
	// A future-dated head forces the database clock's monotonicity guard.
	var flagTime time.Time
	if err := super.QueryRowContext(ctx, `UPDATE attestations SET created_at = clock_timestamp() + interval '1 hour'
		WHERE trail_id = $1 AND type_name = 'flag.changed' AND signed_by IS NULL RETURNING created_at`,
		flag.TrailID).Scan(&flagTime); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIDES_EVENTS_ENABLED", "true")
	body := fmt.Sprintf(`{"trail_id":%q,"name":"build-check","type_name":"ordinary","payload":"{}","signed_by":"ci","signature":"sig","signature_algorithm":"test","manifestation_reason":"approved"}`, flag.TrailID.String())
	var att models.Attestation
	request(http.MethodPost, "/api/v1/attestations", tokenA, body, http.StatusCreated, &att)
	if want := flagTime.Add(time.Microsecond); !att.CreatedAt.Equal(want) {
		t.Fatalf("appended timestamp = %s, want %s", att.CreatedAt, want)
	}

	mustExec("REVOKE INSERT ON integration_events FROM fides_e2e_app")
	defer mustExec("GRANT INSERT ON integration_events TO fides_e2e_app")
	request(http.MethodPost, "/api/v1/attestations", tokenA, body, http.StatusInternalServerError, nil)

	var verdict ledger.Verdict
	request(http.MethodGet, "/api/v1/trails/"+flag.TrailID.String()+"/verify-chain", tokenA, "", http.StatusOK, &verdict)
	if !verdict.Valid || verdict.Count != 2 {
		t.Fatalf("expected a valid 2-link mixed chain after rollback, got %+v", verdict)
	}
	var signed, queued int
	err = super.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM attestations WHERE id = $1 AND signed_by = 'ci' AND signature = 'sig'
		 AND signature_algorithm = 'test' AND manifestation_reason = 'approved'),
		(SELECT count(*) FROM integration_events WHERE org_id = $2 AND event_type = 'compliance.evaluated'
		 AND payload->>'trail_id' = $3 AND payload->>'attestation' = 'build-check'
		 AND payload->>'attestation_type' = 'ordinary' AND payload->>'compliant' = 'true')`,
		att.ID, orgA, flag.TrailID.String()).Scan(&signed, &queued)
	if err != nil || signed != 1 || queued != 1 {
		t.Fatalf("expected one signed attestation and one matching outbox event, got %d and %d, error = %v", signed, queued, err)
	}

	for _, tc := range []struct{ token, sha, packageName string }{
		{tokenA, shaA, "flow-a"}, {tokenB, shaB, "flow-b"},
	} {
		var artifacts []struct {
			SHA    string   `json:"sha256"`
			Status string   `json:"sbom_status"`
			SBOM   []string `json:"sbom"`
		}
		request(http.MethodGet, "/api/v1/artifacts", tc.token, "", http.StatusOK, &artifacts)
		if len(artifacts) != 1 || artifacts[0].SHA != tc.sha || artifacts[0].Status != "Compliant" ||
			len(artifacts[0].SBOM) != 1 || artifacts[0].SBOM[0] != tc.packageName {
			t.Fatalf("unexpected tenant artifacts: %+v", artifacts)
		}
	}
	request(http.MethodPost, "/api/v1/tenant/settings", tokenA, `{"storage":{"storage_driver":"s3"}}`, http.StatusOK, nil)
	request(http.MethodPost, "/api/v1/controls/import-framework", tokenA, `{"framework":"SOC2"}`, http.StatusCreated, nil)
	var driver string
	if err := super.QueryRowContext(ctx, `SELECT storage_driver FROM tenant_storage_settings WHERE org_id = $1`, orgA).Scan(&driver); err != nil || driver != "s3" {
		t.Fatalf("saved storage driver = %q, error = %v", driver, err)
	}
	var controls int
	if err := super.QueryRowContext(ctx, `SELECT COUNT(*) FROM controls WHERE org_id = $1 AND framework = 'SOC2'`, orgA).Scan(&controls); err != nil || controls != len(frameworkCatalogs["SOC2"]) {
		t.Fatalf("imported controls = %d, error = %v", controls, err)
	}

	// Regression: a service-account API key must authenticate under RLS. The
	// pre-auth lookup (authServiceAccountKey) runs on the app pool with no
	// app.current_org set, so if service_accounts/service_account_keys are
	// RLS-protected the row is invisible and every issued key 401s. This is the
	// exact bug the schema-rls.sql exclusion fixes.
	saID := uuid.New()
	mustExec(`INSERT INTO service_accounts (id, org_id, name, role) VALUES ($1,$2,'ci','Auditor')`, saID, orgA)
	full, prefix, secret, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey: %v", err)
	}
	hash, err := crypto.HashPassword(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	mustExec(`INSERT INTO service_account_keys (service_account_id, prefix, key_hash) VALUES ($1,$2,$3)`, saID, prefix, hash)

	p := srv.authServiceAccountKey(context.Background(), full)
	if p == nil {
		t.Fatal("service-account key must authenticate under RLS (pre-auth lookup hidden by RLS)")
	}
	if p.OrgID != orgA || p.Role != auth.RoleAuditor {
		t.Fatalf("wrong principal from key auth: org=%v role=%s (want org=%v role=Auditor)", p.OrgID, p.Role, orgA)
	}
}

// withUserPassword rewrites a space-separated key=value libpq DSN, overriding
// the user and password fields.
func withUserPassword(dsn, user, password string) string {
	fields := map[string]string{}
	var order []string
	for _, kv := range strings.Fields(dsn) {
		if i := strings.IndexByte(kv, '='); i > 0 {
			k := kv[:i]
			if _, seen := fields[k]; !seen {
				order = append(order, k)
			}
			fields[k] = kv[i+1:]
		}
	}
	fields["user"] = user
	fields["password"] = password
	for _, k := range []string{"user", "password"} {
		found := false
		for _, o := range order {
			if o == k {
				found = true
			}
		}
		if !found {
			order = append(order, k)
		}
	}
	var b strings.Builder
	for i, k := range order {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k + "=" + fields[k])
	}
	return b.String()
}
