// Package slack delivers Fides compliance events to a tenant's Slack channel via
// an incoming webhook.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

// Loader resolves a tenant's Slack incoming-webhook URL (the URL is a secret,
// fetched via the secrets provider) and whether notifications are enabled.
type Loader interface {
	SlackWebhook(ctx context.Context, orgID uuid.UUID) (url string, enabled bool, err error)
}

// Sink posts Fides events to Slack.
type Sink struct {
	loader Loader
	http   *http.Client
}

func NewSink(loader Loader) *Sink {
	return &Sink{loader: loader, http: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Sink) Name() string { return "slack" }

// Deliver formats relevant events as a Slack message and posts them.
func (s *Sink) Deliver(ctx context.Context, ev events.Event) error {
	text := formatMessage(ev)
	if text == "" {
		return nil // event type we don't notify on
	}
	url, enabled, err := s.loader.SlackWebhook(ctx, ev.OrgID)
	if err != nil {
		return err
	}
	if !enabled || !strings.HasPrefix(url, "https://") {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack: webhook returned %d", resp.StatusCode)
	}
	return nil
}

func formatMessage(ev events.Event) string {
	switch ev.Type {
	case "snapshot.noncompliant":
		var p struct {
			EnvironmentID string   `json:"environment_id"`
			Shadows       []string `json:"shadows"`
			Drifts        []string `json:"drifts"`
		}
		json.Unmarshal(ev.Payload, &p)
		return fmt.Sprintf(":rotating_light: *Fides: non-compliant snapshot* in environment `%s` — %d shadow(s), %d drift(s).",
			p.EnvironmentID, len(p.Shadows), len(p.Drifts))
	case "compliance.evaluated":
		var p struct {
			TrailID   string `json:"trail_id"`
			Compliant bool   `json:"compliant"`
		}
		json.Unmarshal(ev.Payload, &p)
		icon := ":white_check_mark:"
		state := "compliant"
		if !p.Compliant {
			icon, state = ":x:", "NON-COMPLIANT"
		}
		return fmt.Sprintf("%s *Fides: trail %s is %s*", icon, p.TrailID, state)
	default:
		return ""
	}
}
