package auth

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

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
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		token_hash VARCHAR(64) PRIMARY KEY, org_id UUID NOT NULL, user_id UUID,
		email VARCHAR(255) NOT NULL DEFAULT '', role VARCHAR(50) NOT NULL DEFAULT '',
		kind VARCHAR(20) NOT NULL DEFAULT 'session', expiry TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT now())`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DROP TABLE sessions`) })

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
