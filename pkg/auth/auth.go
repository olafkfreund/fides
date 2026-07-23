// Package auth provides the identity primitives for Fides: an authenticated
// Principal carried on the request context, a CSRF state store and an opaque
// session store for the OAuth2 authorization-code flow, plus helpers to perform
// the token exchange and userinfo lookup.
//
// The state store is in-memory (single-process). The session store is in-memory
// by default but can be Postgres-backed (NewDBSessionStore) so sessions survive
// restarts and are shared across replicas.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Roles, ordered from least to most privileged.
const (
	RoleViewer  = "Viewer"
	RoleWriter  = "Writer"
	RoleAuditor = "Auditor"
	RoleAdmin   = "Admin"
)

// Principal is the authenticated identity for a request. OrgID is the tenant
// boundary and MUST be the sole source of tenant scoping — never trust an
// org_id supplied in a request body or query string.
type Principal struct {
	OrgID  uuid.UUID
	UserID uuid.UUID
	Email  string
	Role   string
	// Kind is "session" for interactive SSO users or "service" for the static
	// API token used by the CLI/MCP automation.
	Kind string
}

type ctxKey struct{}

// WithPrincipal returns a copy of ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the Principal previously stored with WithPrincipal.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// randomToken returns a URL-safe, 256-bit random token.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ----- CSRF state store -----

// StateData is the server-side context bound to an opaque OAuth state value.
type StateData struct {
	OrgID    uuid.UUID
	Provider string
	expiry   time.Time
}

// StateStore issues and validates single-use OAuth state nonces.
type StateStore struct {
	mu sync.Mutex
	m  map[string]StateData
}

func NewStateStore() *StateStore {
	return &StateStore{m: make(map[string]StateData)}
}

// New issues a fresh single-use state value bound to orgID/provider.
func (s *StateStore) New(orgID uuid.UUID, provider string, ttl time.Duration, now time.Time) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = StateData{OrgID: orgID, Provider: provider, expiry: now.Add(ttl)}
	return token, nil
}

// Consume validates a state value and removes it (single use). It returns false
// if the value is unknown or expired.
func (s *StateStore) Consume(state string, now time.Time) (StateData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.m[state]
	if !ok {
		return StateData{}, false
	}
	delete(s.m, state)
	if now.After(data.expiry) {
		return StateData{}, false
	}
	return data, true
}

// ----- Session store -----

type sessionEntry struct {
	principal Principal
	expiry    time.Time
}

// SessionStore maps opaque session tokens to Principals. With db == nil it is an
// in-memory map (single-process); with a *sql.DB it persists sessions to the
// `sessions` table so they survive restarts and are shared across replicas. Only
// a sha256 hash of the token is stored, never the raw token.
type SessionStore struct {
	mu sync.Mutex
	m  map[string]sessionEntry
	db *sql.DB
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]sessionEntry)}
}

// NewDBSessionStore returns a Postgres-backed session store (requires the
// `sessions` table from migration 0020).
func NewDBSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// hashToken returns the sha256 hex of a session token; only the hash is stored,
// so a database leak does not expose usable session tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create stores p and returns a new opaque session token.
func (s *SessionStore) Create(p Principal, ttl time.Duration, now time.Time) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if s.db != nil {
		_, err := s.db.Exec(
			`INSERT INTO sessions (token_hash, org_id, user_id, email, role, kind, expiry)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			hashToken(token), p.OrgID, p.UserID, p.Email, p.Role, p.Kind, now.Add(ttl))
		if err != nil {
			return "", err
		}
		return token, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = sessionEntry{principal: p, expiry: now.Add(ttl)}
	return token, nil
}

// Get returns the Principal for token if the session exists and is unexpired.
// Expired sessions are evicted.
func (s *SessionStore) Get(token string, now time.Time) (Principal, bool) {
	if s.db != nil {
		var p Principal
		var expiry time.Time
		err := s.db.QueryRow(
			`SELECT org_id, user_id, email, role, kind, expiry FROM sessions WHERE token_hash = $1`,
			hashToken(token)).Scan(&p.OrgID, &p.UserID, &p.Email, &p.Role, &p.Kind, &expiry)
		if err != nil {
			return Principal{}, false // sql.ErrNoRows or a real error: treat as unauthenticated
		}
		if now.After(expiry) {
			s.Delete(token)
			return Principal{}, false
		}
		return p, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.m[token]
	if !ok {
		return Principal{}, false
	}
	if now.After(entry.expiry) {
		delete(s.m, token)
		return Principal{}, false
	}
	return entry.principal, true
}

// Delete removes a session (logout).
func (s *SessionStore) Delete(token string) {
	if s.db != nil {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash = $1`, hashToken(token))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// ----- OAuth2 authorization-code helpers -----

// OAuthConfig holds the per-tenant provider settings needed to complete a flow.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	UserInfoURL  string
	RedirectURI  string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeCode performs the authorization-code-for-token exchange. It returns
// the access token on success.
func ExchangeCode(ctx context.Context, client *http.Client, cfg OAuthConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("redirect_uri", cfg.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token endpoint error: %s", tr.Error)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned no access token")
	}
	return tr.AccessToken, nil
}

// UserInfo is the subset of identity claims Fides consumes.
type UserInfo struct {
	Email  string
	Groups []string
}

// FetchUserInfo calls the provider's userinfo endpoint with the bearer token
// and extracts the email and group memberships.
func FetchUserInfo(ctx context.Context, client *http.Client, userInfoURL, accessToken string) (UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return UserInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return UserInfo{}, fmt.Errorf("failed to parse userinfo: %w", err)
	}

	info := UserInfo{}
	if email, ok := raw["email"].(string); ok {
		info.Email = email
	}
	if groups, ok := raw["groups"].([]any); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				info.Groups = append(info.Groups, gs)
			}
		}
	}
	return info, nil
}
