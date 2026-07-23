// Package siem provides an events.Sink that streams integration events to a
// SIEM via the Splunk HTTP Event Collector (HEC). Forwarding change/approval/
// gate events to a SIEM builds the chain of evidence auditors expect for SOC 2 /
// ISO 27001 / FedRAMP (issue #298).
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"fides/pkg/events"
)

// SplunkSink delivers events to a Splunk HEC endpoint.
type SplunkSink struct {
	url    string
	token  string
	client *http.Client
}

// NewSplunkSink builds a HEC sink. url is the full collector endpoint (e.g.
// https://splunk.example.com:8088/services/collector/event); token is the HEC
// token used in the Authorization header.
func NewSplunkSink(url, token string) *SplunkSink {
	return &SplunkSink{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SplunkSink) Name() string { return "splunk-hec" }

// Deliver POSTs one event as a Splunk HEC envelope. It is idempotent only in the
// sense that a redelivery produces a duplicate log line — acceptable for an
// append-only evidence log, and preferable to dropping events.
func (s *SplunkSink) Deliver(ctx context.Context, ev events.Event) error {
	envelope := map[string]any{
		"time":       ev.CreatedAt.Unix(),
		"source":     "fides",
		"sourcetype": "fides:event",
		"event": map[string]any{
			"id":      ev.ID,
			"org_id":  ev.OrgID,
			"type":    ev.Type,
			"payload": ev.Payload,
			"created": ev.CreatedAt,
		},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk hec: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("splunk hec returned status %d", resp.StatusCode)
	}
	return nil
}
