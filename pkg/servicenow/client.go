// Package servicenow is a small REST client for ServiceNow, used by the Fides
// integration sinks: CMDB (Identification & Reconciliation Engine), ITOM
// (Event Management), and ITSM (Table API for change requests / incidents).
//
// The client takes already-resolved credentials in Config (the caller fetches
// the secret via the secrets provider), so it stays decoupled and unit-testable.
package servicenow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthType selects the authentication scheme.
type AuthType string

const (
	AuthBasic  AuthType = "basic"  // service-account username + password
	AuthOAuth2 AuthType = "oauth2" // OAuth2 client-credentials grant
)

// Config holds connection settings with the credential already resolved.
type Config struct {
	InstanceURL string   // https://<instance>.service-now.com
	AuthType    AuthType // basic | oauth2
	ClientID    string   // OAuth client_id, or Basic username
	Secret      string   // OAuth client_secret, or Basic password (resolved)
}

// Client talks to a ServiceNow instance.
type Client struct {
	cfg  Config
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time

	now      func() time.Time
	validate func(string) error // instance URL SSRF guard (overridable in tests)

	maxRetries int
}

// New validates the instance URL and returns a Client.
func New(cfg Config) (*Client, error) {
	cfg.InstanceURL = strings.TrimRight(cfg.InstanceURL, "/")
	if err := validateInstanceURL(cfg.InstanceURL); err != nil {
		return nil, err
	}
	if cfg.AuthType != AuthBasic && cfg.AuthType != AuthOAuth2 {
		return nil, fmt.Errorf("servicenow: unsupported auth type %q", cfg.AuthType)
	}
	return &Client{
		cfg:        cfg,
		http:       &http.Client{Timeout: 20 * time.Second},
		now:        time.Now,
		validate:   validateInstanceURL,
		maxRetries: 3,
	}, nil
}

// doJSON marshals body as JSON (when non-nil) and performs the request via do.
// If out is non-nil the JSON response is decoded into it.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("servicenow: marshal body: %w", err)
		}
	}
	contentType := ""
	if payload != nil {
		contentType = "application/json"
	}
	return c.do(ctx, method, path, contentType, payload, out)
}

// doRaw performs a request with an already-encoded body and explicit content
// type (e.g. the Attachment API, which takes raw file bytes rather than a JSON
// object). If out is non-nil the JSON response is decoded into it.
func (c *Client) doRaw(ctx context.Context, method, path, contentType string, payload []byte, out any) error {
	return c.do(ctx, method, path, contentType, payload, out)
}

// do performs a request with auth, retries, and bounded response reading.
// If out is non-nil the JSON body is decoded into it.
func (c *Client) do(ctx context.Context, method, path, contentType string, payload []byte, out any) error {
	endpoint := c.cfg.InstanceURL + path
	if err := c.validate(endpoint); err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if err := c.authorize(ctx, req); err != nil {
			return err
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue // transport error -> retry
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("servicenow: %s %s -> %d", method, path, resp.StatusCode)
			continue // retryable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("servicenow: %s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("servicenow: decode response: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("servicenow: request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

// validateInstanceURL enforces HTTPS and blocks SSRF to loopback/private/
// link-local addresses.
func validateInstanceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("servicenow: invalid instance url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("servicenow: instance url must use https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("servicenow: instance url has no host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("servicenow: host does not resolve: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("servicenow: instance url resolves to a disallowed address (%s)", ip)
		}
	}
	return nil
}
