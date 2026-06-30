package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStateStoreSingleUse(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStateStore()
	org := uuid.New()

	state, err := s.New(org, "github", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data, ok := s.Consume(state, now)
	if !ok {
		t.Fatalf("expected state to validate")
	}
	if data.OrgID != org || data.Provider != "github" {
		t.Fatalf("state data mismatch: %+v", data)
	}

	// Replaying the same state must fail (single use → CSRF/replay defense).
	if _, ok := s.Consume(state, now); ok {
		t.Fatalf("state must not be reusable")
	}
}

func TestStateStoreExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStateStore()
	state, _ := s.New(uuid.New(), "google", 1*time.Minute, now)

	later := now.Add(2 * time.Minute)
	if _, ok := s.Consume(state, later); ok {
		t.Fatalf("expired state must not validate")
	}
}

func TestStateStoreUnknown(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewStateStore()
	if _, ok := s.Consume("never-issued", now); ok {
		t.Fatalf("unknown state must not validate")
	}
}

func TestSessionStoreLifecycle(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	s := NewSessionStore()
	p := Principal{OrgID: uuid.New(), Email: "a@example.com", Role: RoleAuditor, Kind: "session"}

	token, err := s.Create(p, 1*time.Hour, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, ok := s.Get(token, now)
	if !ok {
		t.Fatalf("expected session to resolve")
	}
	if got.OrgID != p.OrgID || got.Email != p.Email || got.Role != p.Role {
		t.Fatalf("principal mismatch: %+v", got)
	}

	s.Delete(token)
	if _, ok := s.Get(token, now); ok {
		t.Fatalf("session must be gone after Delete")
	}
}

func TestSessionStoreExpiry(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	s := NewSessionStore()
	token, _ := s.Create(Principal{OrgID: uuid.New()}, 1*time.Minute, now)

	if _, ok := s.Get(token, now.Add(2*time.Minute)); ok {
		t.Fatalf("expired session must not resolve")
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	p := &Principal{OrgID: uuid.New(), Role: RoleAdmin}
	ctx := WithPrincipal(context.Background(), p)

	got, ok := FromContext(ctx)
	if !ok || got.OrgID != p.OrgID || got.Role != RoleAdmin {
		t.Fatalf("context round-trip failed: %+v ok=%v", got, ok)
	}

	if _, ok := FromContext(context.Background()); ok {
		t.Fatalf("empty context must not yield a principal")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated")
		}
		seen[tok] = true
	}
}
