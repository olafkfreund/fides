package servicenow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// authorize sets the Authorization header on req per the configured scheme.
func (c *Client) authorize(ctx context.Context, req *http.Request) error {
	switch c.cfg.AuthType {
	case AuthBasic:
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.Secret)
		return nil
	case AuthOAuth2:
		tok, err := c.bearer(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	default:
		return fmt.Errorf("servicenow: unsupported auth type %q", c.cfg.AuthType)
	}
}

// bearer returns a cached OAuth token, fetching a new one if expired.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.tokenExp) {
		return c.token, nil
	}

	tokenURL := c.cfg.InstanceURL + "/oauth_token.do"
	if err := c.validate(tokenURL); err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.Secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("servicenow: token request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("servicenow: token endpoint returned %d", resp.StatusCode)
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", fmt.Errorf("servicenow: parse token response: %w", err)
	}
	if tr.Error != "" || tr.AccessToken == "" {
		return "", fmt.Errorf("servicenow: token error: %s", tr.Error)
	}

	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	c.token = tr.AccessToken
	c.tokenExp = c.now().Add(ttl - 60*time.Second) // refresh a minute early
	return c.token, nil
}
