package api

import (
	"bytes"
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
)

// TestIntegrationSnapshotHonoursAllowlist pins down that an explicitly
// approved image is not reported as a shadow change.
//
// environment_allowlist records an attributed exception (approved_by +
// reason) — the compliance concept of an accepted risk. It had no effect on
// the snapshot verdict: approving an image still left it counted as a shadow
// and the environment permanently non-compliant, so the only route to a green
// verdict was an environment with no third-party images at all. Every real
// environment has some; the one on p510 runs postgres.
//
// Asserts both halves: an unapproved digest is still a shadow (the check must
// not have blanket-suppressed anything), and an approved one is not.
func TestIntegrationSnapshotHonoursAllowlist(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the snapshot allowlist test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Closed via Cleanup, not defer: deferred calls run before any t.Cleanup,
	// so `defer pool.Close()` closed the pool before the cleanups below could
	// use it. Registered here so LIFO runs it last.
	t.Cleanup(func() { pool.Close() })
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	orgID, envID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, orgID, "o-"+orgID.String()[:8])
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, orgID) })
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type,description) VALUES ($1,$2,'e','k8s','')`, envID, orgID)

	// An approved third-party image (think postgres:15-alpine) and an
	// unapproved one that must still be caught.
	const approvedSHA = "aaaa000000000000000000000000000000000000000000000000000000000001"
	const rogueSHA = "bbbb000000000000000000000000000000000000000000000000000000000002"
	mustExec(t, pool,
		`INSERT INTO environment_allowlist (environment_id, artifact_sha256, approved_by, reason)
		 VALUES ($1,$2,$3,$4)`,
		envID, approvedSHA, "olaf@example.com", "upstream base image, no first-party provenance by design")

	t.Setenv("FIDES_API_TOKEN", "unused-but-required")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())
	srv := NewServer(pool, nil, nil)
	token, err := srv.Sessions.Create(auth.Principal{OrgID: orgID, Role: auth.RoleAdmin, Kind: "session"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	snapshot := func(artifacts []any) map[string]any {
		body, _ := json.Marshal(map[string]any{"environment_id": envID.String(), "artifacts": artifacts})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/snapshots", bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("snapshot: HTTP %d", resp.StatusCode)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// Approved only: no shadow, and the environment can actually be compliant.
	out := snapshot([]any{map[string]string{"sha256": approvedSHA, "service_name": "postgres"}})
	if shadows, _ := out["shadow_changes"].([]any); len(shadows) != 0 {
		t.Fatalf("approved digest reported as a shadow change: %v", shadows)
	}
	if compliant, _ := out["compliant"].(bool); !compliant {
		t.Fatalf("compliant = false with only an approved image running; an allowlist that cannot yield a green verdict is not an allowlist")
	}

	// Unapproved alongside it: still caught, still non-compliant.
	out = snapshot([]any{
		map[string]string{"sha256": approvedSHA, "service_name": "postgres"},
		map[string]string{"sha256": rogueSHA, "service_name": "rogue"},
	})
	shadows, _ := out["shadow_changes"].([]any)
	if len(shadows) != 1 {
		t.Fatalf("shadow_changes = %v, want exactly the unapproved digest", shadows)
	}
	if compliant, _ := out["compliant"].(bool); compliant {
		t.Fatal("compliant = true with an unapproved digest running — the allowlist check suppressed too much")
	}
}
