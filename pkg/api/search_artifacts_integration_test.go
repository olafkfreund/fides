package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// Searching by digest must return the trail the artifact was built on.
//
// That is the whole point of the endpoint for a deploy gate: it has a digest
// and needs the trail, because the trail is where the SBOM, the scans and the
// provenance live and what the change gate judges. Without trail_id the only
// way to get there was GET /api/v1/artifacts, which takes no filter, has no
// LIMIT, and runs a per-row SBOM query embedding the payload — the entire
// organisation's SBOMs transferred to learn one id.
func TestSearchArtifactsReturnsTheTrail(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the artifact search integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup rather than defer, and registered first so it runs
	// last: cleanups are LIFO, and deferred calls run *before* any of them. The
	// usual `defer pool.Close()` above a `t.Cleanup` that deletes rows closes
	// the pool first, so the delete runs on a closed pool and its error is
	// discarded — which is why a database used by these tests accumulates
	// organisations that were supposed to be cleaned up.
	t.Cleanup(func() { pool.Close() })

	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'app')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'v1.0.0','abc123')`, trail, flow)
	t.Cleanup(func() {
		if _, err := pool.Exec(`DELETE FROM organizations WHERE id=$1`, org); err != nil {
			t.Errorf("cleanup left organisation %s behind: %v", org, err)
		}
	})

	// Derived from this run's organisation, because artifacts are keyed on
	// sha256 alone — globally, not per organisation. Fixed digests would make
	// two runs against the same database collide on the primary key, and the
	// second one fails in the fixture rather than in anything it was testing.
	digest := func(role string) string {
		sum := sha256.Sum256([]byte(org.String() + "/" + role))
		return hex.EncodeToString(sum[:])
	}
	linked, orphan := digest("linked"), digest("orphan")
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES ($1,$2,$3,'app','docker')`, linked, org, trail)
	// Reported without a trail. The join is a LEFT JOIN precisely so this row
	// still comes back, and it must answer null rather than being dropped or
	// reported as belonging to somebody else's trail.
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,name,type) VALUES ($1,$2,'app','docker')`, orphan, org)

	s := &Server{DB: pool}

	search := func(sha string) []map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/search/artifacts?sha="+sha, nil)
		req = req.WithContext(auth.WithPrincipal(context.Background(),
			&auth.Principal{OrgID: org, Role: auth.RoleViewer, Kind: "service"}))
		rec := httptest.NewRecorder()
		s.handleSearchArtifacts(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}
		return out
	}

	t.Run("an artifact on a trail reports it", func(t *testing.T) {
		got := search(linked)
		if len(got) != 1 {
			t.Fatalf("got %d results, want 1: %v", len(got), got)
		}
		if got[0]["trail_id"] != trail.String() {
			t.Errorf("trail_id = %v, want %s", got[0]["trail_id"], trail)
		}
		// The fields that were already there must not have moved.
		if got[0]["sha256"] != linked || got[0]["git_commit"] != "abc123" {
			t.Errorf("existing fields changed: %v", got[0])
		}
	})

	t.Run("an artifact with no trail reports null", func(t *testing.T) {
		got := search(orphan)
		if len(got) != 1 {
			t.Fatalf("got %d results, want 1: %v", len(got), got)
		}
		// Present and null, not absent: a caller distinguishing "no trail" from
		// "this endpoint does not tell me" needs the key to exist.
		v, ok := got[0]["trail_id"]
		if !ok {
			t.Fatal("trail_id is absent; it should be present and null")
		}
		if v != nil {
			t.Errorf("trail_id = %v, want null", v)
		}
	})
}
