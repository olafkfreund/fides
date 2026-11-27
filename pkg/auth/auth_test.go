package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestExchangeCodeConfiguredEndpoint(t *testing.T) {
	cfg := OAuthConfig{
		ClientID:     "fides",
		ClientSecret: "fake-secret",
		TokenURL:     "https://10.20.30.40:8443/tenant/oauth/token",
		RedirectURI:  "https://fides.example.test/api/v1/auth/callback",
	}
	for _, tc := range []struct {
		name, response, wantError string
		status                    int
	}{
		{"success", `{"access_token":"fake-access-token"}`, "", http.StatusOK},
		{"oauth error", `{"error":"invalid_grant"}`, "invalid_grant", http.StatusOK},
		{"http error", `{"error":"invalid_client"}`, "status 401", http.StatusUnauthorized},
		{"missing token", `{}`, "no access token", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.String() != cfg.TokenURL {
					t.Errorf("request = %s %s, want POST %s", r.Method, r.URL, cfg.TokenURL)
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
					t.Error("expected a form request that accepts JSON")
				}
				defer r.Body.Close()
				if err := r.ParseForm(); err != nil {
					return nil, fmt.Errorf("parse token request: %w", err)
				}
				want := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {"fake+code"},
					"client_id":     {cfg.ClientID},
					"client_secret": {cfg.ClientSecret},
					"redirect_uri":  {cfg.RedirectURI},
				}
				if r.PostForm.Encode() != want.Encode() {
					t.Error("unexpected authorization-code form")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			})}
			token, err := ExchangeCode(t.Context(), client, cfg, "fake+code")
			if tc.wantError == "" {
				if err != nil || token != "fake-access-token" {
					t.Fatalf("expected the provider access token, got error %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) || token != "" {
				t.Fatalf("expected error containing %q and no access token, got error %v", tc.wantError, err)
			}
		})
	}
}

func TestFetchUserInfoConfiguredEndpoint(t *testing.T) {
	const endpoint = "https://10.20.30.40:8443/tenant/oauth/userinfo"
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.String() != endpoint {
					t.Errorf("request = %s %s, want GET %s", r.Method, r.URL, endpoint)
				}
				if r.Header.Get("Authorization") != "Bearer fake-access-token" || r.Header.Get("Accept") != "application/json" {
					t.Error("expected bearer authorization and JSON acceptance")
				}
				const body = `{"email":"dev@example.test","groups":["engineering","audit"]}`
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			info, err := FetchUserInfo(t.Context(), client, endpoint, "fake-access-token")
			if status == http.StatusUnauthorized {
				if err == nil || info.Email != "" || len(info.Groups) != 0 {
					t.Fatalf("expected an error and no identity claims, got %+v, %v", info, err)
				}
				return
			}
			if err != nil || info.Email != "dev@example.test" || !slices.Equal(info.Groups, []string{"engineering", "audit"}) {
				t.Fatalf("unexpected user info %+v, %v", info, err)
			}
		})
	}
}

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
