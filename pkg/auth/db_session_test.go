package auth

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// sessionsDDL is the minimal table the DB-backed session store needs; inlined so
// these tests are self-contained (no migration-path coupling).
const sessionsDDL = `CREATE TABLE IF NOT EXISTS sessions (
	token_hash VARCHAR(64) PRIMARY KEY, org_id UUID NOT NULL, user_id UUID,
	email VARCHAR(255) NOT NULL DEFAULT '', role VARCHAR(50) NOT NULL DEFAULT '',
	kind VARCHAR(20) NOT NULL DEFAULT 'session', expiry TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ DEFAULT now())`

// resetSessions gives the test a clean sessions table. It drops first so the
// test is independent of any rows a prior test left behind — the post-test DROP
// can't be relied on because `defer db.Close()` runs before t.Cleanup, closing
// the pool the cleanup would use.
func resetSessions(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DROP TABLE IF EXISTS sessions`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := db.Exec(sessionsDDL); err != nil {
		t.Fatalf("create table: %v", err)
	}
}

// TestDBSessionCleanupExpired verifies CleanupExpired removes only expired rows.
func TestDBSessionCleanupExpired(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the DB session cleanup test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	resetSessions(t, db)

	store := NewDBSessionStore(db)
	now := time.Now()
	p := Principal{OrgID: uuid.New(), Role: RoleViewer, Kind: "session"}
	expiredTok, _ := store.Create(p, -time.Hour, now) // already expired
	activeTok, _ := store.Create(p, time.Hour, now)   // still valid

	n, err := store.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("CleanupExpired removed %d, want 1", n)
	}
	if _, ok := store.Get(expiredTok, now); ok {
		t.Fatal("expired session should be gone")
	}
	if _, ok := store.Get(activeTok, now); !ok {
		t.Fatal("active session should survive cleanup")
	}
}

// TestDBSessionStore exercises the Postgres-backed session store: create, look
// up, expiry eviction, delete, and that only a hash of the token is stored.
func TestDBSessionStore(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the DB session store test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	resetSessions(t, db)

	store := NewDBSessionStore(db)
	now := time.Now()
	p := Principal{OrgID: uuid.New(), UserID: uuid.New(), Email: "a@b.com", Role: RoleAdmin, Kind: "session"}

	token, err := store.Create(p, time.Hour, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The raw token must NOT be stored — only its hash.
	var rawCount int
	db.QueryRow(`SELECT count(*) FROM sessions WHERE token_hash = $1`, token).Scan(&rawCount)
	if rawCount != 0 {
		t.Fatal("raw token found in token_hash column; must store only the hash")
	}

	got, ok := store.Get(token, now)
	if !ok || got.OrgID != p.OrgID || got.Role != RoleAdmin || got.Email != "a@b.com" || got.Kind != "session" {
		t.Fatalf("Get returned %+v ok=%v, want the created principal", got, ok)
	}

	// Expired lookup fails and evicts.
	if _, ok := store.Get(token, now.Add(2*time.Hour)); ok {
		t.Fatal("expected expired session to be rejected")
	}
	var remaining int
	db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("expired session not evicted: %d rows remain", remaining)
	}

	// Delete removes an active session.
	token2, _ := store.Create(p, time.Hour, now)
	store.Delete(token2)
	if _, ok := store.Get(token2, now); ok {
		t.Fatal("expected deleted session to be gone")
	}
}
