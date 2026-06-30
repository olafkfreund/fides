// Package webhooks provides an events.Sink that delivers integration events to
// per-tenant HTTP endpoints, signed with HMAC-SHA256 so receivers can verify
// authenticity and reject replays. It is the generic consumer of the event
// outbox used for CI/CD gating, ChatOps, and SIEM forwarding.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

// Target is a resolved webhook endpoint for a tenant, with its signing secret
// already retrieved from the secrets provider.
type Target struct {
	URL    string
	Secret string
}

// Loader returns the webhook targets that should receive an event of eventType
// for the given org. Implementations resolve config + secrets (DB-backed in
// production, faked in tests).
type Loader interface {
	Targets(ctx context.Context, orgID uuid.UUID, eventType string) ([]Target, error)
}

// Clock allows tests to control the signature timestamp.
type Clock func() time.Time

// Sink delivers events to a tenant's configured webhooks.
type Sink struct {
	loader   Loader
	client   *http.Client
	now      Clock
	validate func(string) error // URL/SSRF guard; overridable in tests
}

// NewSink builds a webhook Sink. The HTTP client uses a bounded timeout.
func NewSink(loader Loader) *Sink {
	return &Sink{
		loader:   loader,
		client:   &http.Client{Timeout: 10 * time.Second},
		now:      time.Now,
		validate: validateTargetURL,
	}
}

func (s *Sink) Name() string { return "webhook" }

// envelope is the JSON body delivered to webhook receivers.
type envelope struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	OrgID   string          `json:"org_id"`
	Payload json.RawMessage `json:"payload"`
	SentAt  string          `json:"sent_at"`
}

// Deliver sends the event to every configured target. A failure for any target
// returns an error so the dispatcher retries; receivers MUST dedupe on the
// X-Fides-Event-Id header (delivery is at-least-once).
func (s *Sink) Deliver(ctx context.Context, ev events.Event) error {
	targets, err := s.loader.Targets(ctx, ev.OrgID, ev.Type)
	if err != nil {
		return fmt.Errorf("load webhook targets: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}

	ts := strconv.FormatInt(s.now().Unix(), 10)
	body, err := json.Marshal(envelope{
		ID:      ev.ID.String(),
		Type:    ev.Type,
		OrgID:   ev.OrgID.String(),
		Payload: ev.Payload,
		SentAt:  ts,
	})
	if err != nil {
		return fmt.Errorf("marshal webhook envelope: %w", err)
	}

	var errs []error
	for _, t := range targets {
		if err := s.post(ctx, t, ev, ts, body); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.URL, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Sink) post(ctx context.Context, t Target, ev events.Event, ts string, body []byte) error {
	if err := s.validate(t.URL); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fides-webhooks/1")
	req.Header.Set("X-Fides-Event-Id", ev.ID.String())
	req.Header.Set("X-Fides-Event-Type", ev.Type)
	req.Header.Set("X-Fides-Timestamp", ts)
	req.Header.Set("X-Fides-Signature", Sign(t.Secret, ts, body))

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// Sign computes the webhook signature over "timestamp.body" using HMAC-SHA256,
// formatted as "sha256=<hex>". Receivers recompute and compare in constant time,
// and should reject stale timestamps to prevent replay.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// validateTargetURL enforces HTTPS and blocks SSRF to loopback/private/
// link-local addresses (incl. the cloud metadata endpoint 169.254.169.254).
func validateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook url must use https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook url has no host")
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("webhook host does not resolve: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("webhook url resolves to a disallowed address (%s)", ip)
		}
	}
	return nil
}
