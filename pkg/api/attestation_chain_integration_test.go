package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the attestation-chain integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "session"})

	// Record two attestations with deliberately non-canonical JSON (unsorted keys)
	// to exercise the JSONB canonicalization round-trip.
	base := time.Now().Add(-time.Hour)
	for i, payload := range []string{`{"b":2,"a":1}`, `{"z":true,"m":"x"}`} {
		ch, prev, err := s.attestationChain(ctx, trail, "att", "type", payload, true)
		if err != nil {
			t.Fatalf("chain[%d]: %v", i, err)
		}
		mustExec(t, pool,
			`INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,content_hash,prev_hash,created_at)
			 VALUES ($1,$2,'att','type',$3,true,$4,$5,$6)`,
			uuid.New(), trail, payload, ch, prev, base.Add(time.Duration(i)*time.Second))
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
