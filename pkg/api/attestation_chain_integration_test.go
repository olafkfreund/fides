package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
	"fides/pkg/ledger"
)

// End-to-end: attestations recorded with the hash chain verify as valid through
// the JSONB round-trip, and any tampering is detected. Gated by FIDES_TEST_DB_DSN.
func TestAttestationChainIntegration(t *testing.T) {
	pool, org, trail := attestationChainFixture(t)
	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	// Seed historical rows directly so verification remains independent of the
	// append implementation. Unsorted keys exercise the JSONB round-trip.
	base := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	prev := ""
	for i, payload := range []string{`{"b":2,"a":1}`, `{"z":true,"m":"x"}`} {
		ch := ledger.ContentHash(trail.String(), "att", "type", ledger.CanonicalJSON(payload), true, prev)
		mustExec(t, pool,
			`INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,content_hash,prev_hash,created_at)
			 VALUES ($1,$2,'att','type',$3,true,$4,$5,$6)`,
			uuid.New(), trail, payload, ch, prev, base.Add(time.Duration(i)*time.Second))
		prev = ch
	}

	verdict := verifyChain(t, s, ctx, trail)
	if !verdict.Valid || verdict.Count != 2 {
		t.Fatalf("expected a valid 2-link chain, got %+v", verdict)
	}

	// Tamper with the first attestation's payload directly in the DB.
	mustExec(t, pool, `UPDATE attestations SET payload='{"a":999}' WHERE trail_id=$1 AND created_at=$2`, trail, base)
	if v := verifyChain(t, s, ctx, trail); v.Valid {
		t.Fatalf("tampered chain must be invalid, got %+v", v)
	}
}

func attestationChainFixture(t *testing.T) (*sql.DB, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the attestation-chain integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Keep the pool open until the fixture rows are deleted.
	t.Cleanup(func() { pool.Close() })
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	applyAttestationValidationMigration(t, pool)

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	t.Cleanup(func() { mustExec(t, pool, `DELETE FROM organizations WHERE id=$1`, org) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	return pool, org, trail
}

func TestConcurrentAttestationAppendsIntegration(t *testing.T) {
	pool, org, trail := attestationChainFixture(t)
	t.Setenv("FIDES_RLS_ENABLED", "false")
	t.Setenv("FIDES_EVENTS_ENABLED", "false")

	s := &Server{DB: pool, Sessions: auth.NewSessionStore()}
	token, err := s.Sessions.Create(auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const appends = 16
	const appendPath = "/api/v1/attestations"
	ready := make(chan struct{}, appends)
	start := make(chan struct{})
	routes := s.Routes()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == appendPath {
			ready <- struct{}{}
			select {
			case <-start:
			case <-r.Context().Done():
				return
			}
		}
		routes.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	request := func(method, path, body string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		req.Header.Set("Content-Type", "application/json")
		return server.Client().Do(req)
	}
	results := make(chan error, appends)
	for i := range appends {
		go func() {
			body := fmt.Sprintf(`{"trail_id":%q,"name":"append-%d","type_name":"ordinary","payload":"{}"}`, trail.String(), i)
			resp, err := request(http.MethodPost, appendPath, body)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode != http.StatusCreated {
					err = fmt.Errorf("HTTP %s", resp.Status)
				}
			}
			if err != nil {
				err = fmt.Errorf("append %d: %w", i, err)
			}
			results <- err
		}()
	}
	// Release requests only after every POST has reached the server.
	for range appends {
		select {
		case <-ready:
		case err := <-results:
			t.Fatalf("append ended before the start barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("waiting for concurrent requests: %v", ctx.Err())
		}
	}
	close(start)
	for range appends {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}

	var count int
	if err := pool.QueryRowContext(ctx, `SELECT count(*) FROM attestations WHERE trail_id = $1`, trail).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != appends {
		t.Fatalf("stored %d attestations, want %d", count, appends)
	}
	var eventCount int
	if err := pool.QueryRowContext(ctx, `SELECT count(*) FROM integration_events WHERE org_id = $1`, org).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("stored %d outbox events with events disabled, want 0", eventCount)
	}
	resp, err := request(http.MethodGet, "/api/v1/trails/"+trail.String()+"/verify-chain", "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify-chain: HTTP %s", resp.Status)
	}
	var verdict ledger.Verdict
	if err := json.NewDecoder(resp.Body).Decode(&verdict); err != nil {
		t.Fatal(err)
	}
	if !verdict.Valid || verdict.Count != appends {
		t.Fatalf("expected a valid %d-link chain, got %+v", appends, verdict)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec: %v\nSQL: %.80s", err, q)
	}
}

func verifyChain(t *testing.T, s *Server, ctx context.Context, trail uuid.UUID) ledger.Verdict {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trails/"+trail.String()+"/verify-chain", nil).WithContext(ctx)
	req.SetPathValue("id", trail.String())
	rec := httptest.NewRecorder()
	s.handleVerifyTrailChain(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-chain HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var v ledger.Verdict
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode verdict: %v", err)
	}
	return v
}
